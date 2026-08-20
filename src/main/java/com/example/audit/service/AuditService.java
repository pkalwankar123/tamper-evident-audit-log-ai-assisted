package com.example.audit.service;

import com.example.audit.api.ApiModels;
import com.example.audit.domain.AuditRecord;
import com.example.audit.domain.ChainCheckpoint;
import com.example.audit.domain.IdempotencyRecord;
import com.example.audit.domain.RedactionEntry;
import com.example.audit.repository.AuditRecordRepository;
import com.example.audit.repository.ChainCheckpointRepository;
import com.example.audit.repository.IdempotencyRecordRepository;
import com.example.audit.repository.RedactionEntryRepository;
import com.example.audit.security.AuditAccessPolicy;
import com.example.audit.security.AuthenticatedActor;
import com.example.audit.util.CanonicalJson;
import com.example.audit.util.Hashing;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.persistence.criteria.Predicate;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Audit log behaviour, with authorization enforced here rather than only at the web
 * layer.
 *
 * <p>Every public method takes an {@link AuthenticatedActor} and consults
 * {@link AuditAccessPolicy} before touching data. That placement is deliberate: it means
 * tenant isolation and actor ownership hold for any caller of this class, and it makes
 * the guarantees testable without HTTP - see {@code ServiceLayerAuthorizationTest},
 * which drives these methods directly and asserts that actor-a cannot reach actor-b or
 * tenant-b data.
 *
 * <p>Each tenant has its own hash chain. A shared global chain would make a
 * tenant-scoped verification impossible to express - the verifier would see gaps
 * wherever another tenant's records were filtered out - so the chain is partitioned
 * along the same boundary the authorization model uses.
 */
@Service
public class AuditService {
    public static final String GENESIS_HASH = "0".repeat(64);
    private static final String REDACTED = "[REDACTED]";

    private final AuditRecordRepository records;
    private final RedactionEntryRepository redactions;
    private final ChainCheckpointRepository checkpoints;
    private final IdempotencyRecordRepository idempotencyRecords;
    private final CanonicalJson canonicalJson;
    private final AuditAccessPolicy accessPolicy;
    private final AuditAppender appender;
    private final ChainHeadService chainHeadService;
    private final SigningService signingService;

    public AuditService(AuditRecordRepository records, RedactionEntryRepository redactions,
                        ChainCheckpointRepository checkpoints, IdempotencyRecordRepository idempotencyRecords,
                        CanonicalJson canonicalJson, AuditAccessPolicy accessPolicy, AuditAppender appender,
                        ChainHeadService chainHeadService, SigningService signingService) {
        this.records = records;
        this.redactions = redactions;
        this.checkpoints = checkpoints;
        this.idempotencyRecords = idempotencyRecords;
        this.canonicalJson = canonicalJson;
        this.accessPolicy = accessPolicy;
        this.appender = appender;
        this.chainHeadService = chainHeadService;
        this.signingService = signingService;
    }

    // ------------------------------------------------------------------
    // Append
    // ------------------------------------------------------------------

    /**
     * Appends one record. The actor and tenant written onto it come from {@code actor}
     * and are not influenced by the request in any way.
     *
     * <p>Intentionally not {@code @Transactional}: the idempotency lookup and the retry
     * that follows a lost insert race have to observe another transaction's commit, so
     * the transactional boundary is one level down in {@link AuditAppender}.
     */
    public ApiModels.AppendOutcome append(AuthenticatedActor actor, ApiModels.CreateAuditEventRequest request,
                                          String idempotencyKey) {
        Instant eventTime = (request.timestamp() == null ? Instant.now() : request.timestamp())
                .truncatedTo(ChronoUnit.MILLIS);
        String canonicalPayload = canonicalJson.write(request.payload());
        String requestHash = requestHash(actor, request, canonicalPayload);

        Optional<ApiModels.AppendOutcome> replay = replayIfSeen(actor, idempotencyKey, requestHash);
        if (replay.isPresent()) {
            return replay.get();
        }

        chainHeadService.ensureExists(actor.tenantId());
        try {
            AuditRecord saved = appender.append(actor, request.eventType(), request.resourceType(),
                    request.resourceId(), eventTime, canonicalPayload, idempotencyKey, requestHash);
            return new ApiModels.AppendOutcome(toResponse(saved), false);
        } catch (DataIntegrityViolationException lostRace) {
            // A concurrent request with the same idempotency key committed first; that
            // append rolled back, so serve the winner rather than reporting an error.
            return replayIfSeen(actor, idempotencyKey, requestHash)
                    .orElseThrow(() -> lostRace);
        }
    }

    private Optional<ApiModels.AppendOutcome> replayIfSeen(AuthenticatedActor actor, String idempotencyKey,
                                                           String requestHash) {
        if (idempotencyKey == null || idempotencyKey.isBlank()) {
            return Optional.empty();
        }
        return idempotencyRecords.findByTenantIdAndIdempotencyKey(actor.tenantId(), idempotencyKey)
                .map(existing -> {
                    if (!existing.getRequestHash().equals(requestHash)) {
                        throw new IdempotencyConflictException("Idempotency-Key '" + idempotencyKey
                                + "' was already used for a different request body");
                    }
                    AuditRecord original = records.findById(existing.getRecordId())
                            .orElseThrow(() -> new IllegalStateException(
                                    "Idempotency key references a record that no longer exists"));
                    return new ApiModels.AppendOutcome(toResponse(original), true);
                });
    }

    /**
     * Fingerprints what the <em>caller</em> sent, so a genuine retry of the same request
     * matches.
     *
     * <p>Only the client-supplied timestamp is included, never the server-side default.
     * Folding {@code Instant.now()} in here made every retry look like a different
     * request, so a replay was reported as a 409 conflict and the idempotency guarantee
     * silently did nothing - the failure mode
     * {@code AuditLogIntegrationTest.replayWithSameKeyReturnsOriginal} pins.
     */
    private String requestHash(AuthenticatedActor actor, ApiModels.CreateAuditEventRequest request,
                               String canonicalPayload) {
        String clientTimestamp = request.timestamp() == null
                ? "server-assigned"
                : request.timestamp().truncatedTo(ChronoUnit.MILLIS).toString();
        return Hashing.sha256(String.join("|", actor.tenantId(), actor.actorId(), request.eventType(),
                request.resourceType(), request.resourceId(), clientTimestamp, canonicalPayload));
    }

    // ------------------------------------------------------------------
    // Query
    // ------------------------------------------------------------------

    @Transactional(readOnly = true)
    public Page<ApiModels.AuditEventResponse> query(AuthenticatedActor actor, String requestedActorId,
                                                     String resourceType, String resourceId, String eventType,
                                                     Instant from, Instant to, boolean includeArchived,
                                                     Pageable pageable) {
        String scopedActorId = accessPolicy.resolveQueryActorId(actor, requestedActorId);
        Specification<AuditRecord> specification = (root, query, builder) -> {
            List<Predicate> predicates = new ArrayList<>();
            // Tenant is never optional and is never taken from the request.
            predicates.add(builder.equal(root.get("tenantId"), actor.tenantId()));
            if (scopedActorId != null) predicates.add(builder.equal(root.get("actorId"), scopedActorId));
            if (resourceType != null) predicates.add(builder.equal(root.get("resourceType"), resourceType));
            if (resourceId != null) predicates.add(builder.equal(root.get("resourceId"), resourceId));
            if (eventType != null) predicates.add(builder.equal(root.get("eventType"), eventType));
            if (from != null) predicates.add(builder.greaterThanOrEqualTo(root.get("timestamp"), from));
            if (to != null) predicates.add(builder.lessThanOrEqualTo(root.get("timestamp"), to));
            if (!includeArchived) predicates.add(builder.isFalse(root.get("archived")));
            return builder.and(predicates.toArray(Predicate[]::new));
        };
        return records.findAll(specification, pageable).map(this::toResponse);
    }

    @Transactional(readOnly = true)
    public ApiModels.AuditEventResponse findById(AuthenticatedActor actor, UUID id) {
        AuditRecord record = records.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Audit record not found"));
        accessPolicy.requireRecordAccess(actor, record);
        return toResponse(record);
    }

    // ------------------------------------------------------------------
    // Redaction
    // ------------------------------------------------------------------

    @Transactional
    public ApiModels.RedactionResponse redact(AuthenticatedActor actor, UUID id,
                                              ApiModels.RedactionRequest request) {
        accessPolicy.requireAdmin(actor, "redact an audit record");
        AuditRecord record = records.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Audit record not found"));
        // Tenant isolation before anything else: an administrator of tenant A must not
        // be able to redact - or even confirm the existence of - a record in tenant B.
        accessPolicy.requireTenant(actor, record.getTenantId());

        JsonNode root = canonicalJson.read(record.getPayloadJson()).deepCopy();
        if (!(root instanceof ObjectNode objectNode)) {
            throw new IllegalArgumentException("Payload root must be a JSON object for structured redaction");
        }
        if (objectNode.at(request.fieldPath()).isMissingNode()) {
            throw new IllegalArgumentException("JSON Pointer field path does not exist: " + request.fieldPath());
        }
        replaceAtPointer(objectNode, request.fieldPath(), REDACTED);

        String previousPayloadHash = Hashing.sha256(record.getPayloadJson());
        String newPayload = canonicalJson.write(objectNode);
        String newPayloadHash = Hashing.sha256(newPayload);
        RedactionEntry prior = redactions.findTopByRecordIdOrderBySequenceNumberDesc(id).orElse(null);
        long sequence = prior == null ? 1 : prior.getSequenceNumber() + 1;
        String previousEntryHash = prior == null ? GENESIS_HASH : prior.getEntryHash();
        Instant createdAt = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        // The redacting actor is the authenticated principal, not a body field.
        String entryHash = calculateRedactionHash(id, sequence, request.fieldPath(), request.reason(),
                actor.actorId(), createdAt, previousPayloadHash, newPayloadHash, previousEntryHash);
        redactions.save(new RedactionEntry(record.getTenantId(), id, sequence, request.fieldPath(),
                request.reason(), actor.actorId(), createdAt, previousPayloadHash, newPayloadHash,
                previousEntryHash, entryHash));
        record.setPayloadJson(newPayload);
        records.save(record);
        return new ApiModels.RedactionResponse(id, request.fieldPath(), REDACTED, entryHash);
    }

    // ------------------------------------------------------------------
    // Verification
    // ------------------------------------------------------------------

    @Transactional(readOnly = true)
    public ApiModels.VerificationResponse verify(AuthenticatedActor actor) {
        List<AuditRecord> all = records.findByTenantIdOrderByChainIndexAsc(actor.tenantId());
        String expectedPrevious = GENESIS_HASH;
        long expectedIndex = 1;
        for (AuditRecord record : all) {
            if (record.getChainIndex() != expectedIndex) {
                return broken(record, "CHAIN_INDEX_GAP", "Expected chain index " + expectedIndex);
            }
            if (!Objects.equals(record.getPreviousHash(), expectedPrevious)) {
                return broken(record, "PREVIOUS_HASH_MISMATCH", "Record does not link to its predecessor");
            }
            String calculated = calculateRecordHash(record.getTenantId(), record.getChainIndex(),
                    record.getEventType(), record.getActorId(), record.getResourceType(), record.getResourceId(),
                    record.getTimestamp(), record.getIngestedAt(), record.getPayloadCommitment(),
                    record.getPreviousHash());
            if (!Objects.equals(calculated, record.getRecordHash())) {
                return broken(record, "RECORD_HASH_MISMATCH", "Immutable record content was modified");
            }
            String redactionProblem = verifyPayloadAndRedactions(record);
            if (redactionProblem != null) {
                return broken(record, "PAYLOAD_OR_REDACTION_LEDGER_MISMATCH", redactionProblem);
            }
            expectedPrevious = record.getRecordHash();
            expectedIndex++;
        }

        ApiModels.VerificationResponse checkpointProblem = verifyCheckpoints(actor.tenantId(), all);
        if (checkpointProblem != null) {
            return checkpointProblem;
        }
        return new ApiModels.VerificationResponse(true, (long) all.size(), null, null, null, "Chain is intact");
    }

    /**
     * Checks the chain against previously signed commitments.
     *
     * <p>Link checking alone cannot catch a consistent rewrite: delete the last three
     * records, or rebuild the whole chain, and every remaining link still verifies.
     * Checkpoints do catch it, because the service already attested to a specific
     * {@code recordHash} at a specific index and that attestation is signed.
     */
    private ApiModels.VerificationResponse verifyCheckpoints(String tenantId, List<AuditRecord> chain) {
        for (ChainCheckpoint checkpoint : checkpoints.findByTenantIdOrderByChainIndexAsc(tenantId)) {
            if (!signingService.verify(checkpoint.signingPayload(), checkpoint.getSignatureBase64(),
                    checkpoint.getKeyId())) {
                return new ApiModels.VerificationResponse(false, (long) chain.size(), null,
                        checkpoint.getChainIndex(), "CHECKPOINT_SIGNATURE_INVALID",
                        "Checkpoint at index " + checkpoint.getChainIndex()
                                + " is not signed by a key this service recognises");
            }
            if (chain.size() < checkpoint.getChainIndex()) {
                return new ApiModels.VerificationResponse(false, (long) chain.size(), null,
                        checkpoint.getChainIndex(), "CHECKPOINT_MISSING_RECORDS",
                        "A signed checkpoint exists for index " + checkpoint.getChainIndex()
                                + " but the chain now ends at " + chain.size() + " - records were removed");
            }
            AuditRecord atIndex = chain.get((int) checkpoint.getChainIndex() - 1);
            if (!atIndex.getRecordHash().equals(checkpoint.getRecordHash())) {
                return broken(atIndex, "CHECKPOINT_MISMATCH",
                        "Record at index " + checkpoint.getChainIndex()
                                + " does not match the signed checkpoint for that index");
            }
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Retention / archive
    // ------------------------------------------------------------------

    /**
     * Soft-archives records older than the cutoff, within the tenant only.
     *
     * <p>Archiving marks a flag and nothing else - no field that feeds a hash is
     * touched - so an archived record still verifies. {@code RetentionAndArchiveTest}
     * asserts that explicitly rather than relying on the claim.
     */
    @Transactional
    public int archiveOlderThan(AuthenticatedActor actor, Instant cutoff) {
        accessPolicy.requireAdmin(actor, "archive audit records");
        List<AuditRecord> candidates =
                records.findByTenantIdAndTimestampBeforeAndArchivedFalse(actor.tenantId(), cutoff);
        candidates.forEach(record -> record.setArchived(true));
        records.saveAll(candidates);
        return candidates.size();
    }

    /** Expires idempotency keys past their retention window. */
    @Transactional
    public int purgeExpiredIdempotencyKeys(Instant cutoff) {
        List<IdempotencyRecord> expired = idempotencyRecords.findByCreatedAtBefore(cutoff);
        idempotencyRecords.deleteAll(expired);
        return expired.size();
    }

    // ------------------------------------------------------------------
    // Read helpers used by export
    // ------------------------------------------------------------------

    @Transactional(readOnly = true)
    public List<AuditRecord> tenantRecords(AuthenticatedActor actor) {
        return records.findByTenantIdOrderByChainIndexAsc(actor.tenantId());
    }

    @Transactional(readOnly = true)
    public List<ApiModels.RedactionEntryView> redactionViews(UUID recordId) {
        return redactions.findByRecordIdOrderBySequenceNumberAsc(recordId).stream()
                .map(entry -> new ApiModels.RedactionEntryView(entry.getSequenceNumber(), entry.getFieldPath(),
                        entry.getReason(), entry.getActorId(), entry.getCreatedAt(),
                        entry.getPreviousPayloadHash(), entry.getNewPayloadHash(), entry.getPreviousEntryHash(),
                        entry.getEntryHash()))
                .toList();
    }

    public ApiModels.AuditEventResponse toResponse(AuditRecord record) {
        return new ApiModels.AuditEventResponse(record.getId(), record.getTenantId(), record.getChainIndex(),
                record.getEventType(), record.getActorId(), record.getResourceType(), record.getResourceId(),
                canonicalJson.read(record.getPayloadJson()), record.getTimestamp(), record.getIngestedAt(),
                record.getPayloadCommitment(), record.getPreviousHash(), record.getRecordHash(),
                record.isArchived());
    }

    // ------------------------------------------------------------------
    // Hashing - shared with ExportVerifier so a recipient computes identical bytes
    // ------------------------------------------------------------------

    private String verifyPayloadAndRedactions(AuditRecord record) {
        List<RedactionEntry> entries = redactions.findByRecordIdOrderBySequenceNumberAsc(record.getId());
        String currentPayloadHash = Hashing.sha256(record.getPayloadJson());
        if (entries.isEmpty()) {
            return currentPayloadHash.equals(record.getPayloadCommitment())
                    ? null : "Payload changed without a redaction entry";
        }
        String expectedPayloadHash = record.getPayloadCommitment();
        String expectedPreviousEntry = GENESIS_HASH;
        long expectedSequence = 1;
        for (RedactionEntry entry : entries) {
            if (entry.getSequenceNumber() != expectedSequence) return "Redaction sequence is not contiguous";
            if (!entry.getPreviousEntryHash().equals(expectedPreviousEntry)) return "Redaction entry link is invalid";
            if (!entry.getPreviousPayloadHash().equals(expectedPayloadHash)) {
                return "Redaction payload transition is invalid";
            }
            String calculated = calculateRedactionHash(entry.getRecordId(), entry.getSequenceNumber(),
                    entry.getFieldPath(), entry.getReason(), entry.getActorId(), entry.getCreatedAt(),
                    entry.getPreviousPayloadHash(), entry.getNewPayloadHash(), entry.getPreviousEntryHash());
            if (!calculated.equals(entry.getEntryHash())) return "Redaction entry hash is invalid";
            expectedPayloadHash = entry.getNewPayloadHash();
            expectedPreviousEntry = entry.getEntryHash();
            expectedSequence++;
        }
        return currentPayloadHash.equals(expectedPayloadHash)
                ? null : "Current payload does not match the latest authorized redaction";
    }

    private ApiModels.VerificationResponse broken(AuditRecord record, String type, String details) {
        return new ApiModels.VerificationResponse(false, record.getChainIndex() - 1, record.getId(),
                record.getChainIndex(), type, details);
    }

    public static String calculateRecordHash(String tenantId, long index, String eventType, String actorId,
                                             String resourceType, String resourceId, Instant timestamp,
                                             Instant ingestedAt, String payloadCommitment, String previousHash) {
        return Hashing.sha256(String.join("|", tenantId, Long.toString(index), eventType, actorId, resourceType,
                resourceId, timestamp.toString(), ingestedAt.toString(), payloadCommitment, previousHash));
    }

    public static String calculateRedactionHash(UUID recordId, long sequence, String fieldPath, String reason,
                                                String actorId, Instant createdAt, String previousPayloadHash,
                                                String newPayloadHash, String previousEntryHash) {
        return Hashing.sha256(String.join("|", recordId.toString(), Long.toString(sequence), fieldPath, reason,
                actorId, createdAt.toString(), previousPayloadHash, newPayloadHash, previousEntryHash));
    }

    private static void replaceAtPointer(ObjectNode root, String pointer, String replacement) {
        if (!pointer.startsWith("/") || pointer.length() < 2) {
            throw new IllegalArgumentException("fieldPath must be a JSON Pointer such as /account/number");
        }
        String[] parts = pointer.substring(1).split("/");
        JsonNode current = root;
        for (int i = 0; i < parts.length - 1; i++) {
            current = current.get(unescape(parts[i]));
            if (!(current instanceof ObjectNode)) {
                throw new IllegalArgumentException("Only object-field JSON Pointers are supported");
            }
        }
        ((ObjectNode) current).put(unescape(parts[parts.length - 1]), replacement);
    }

    private static String unescape(String token) {
        return token.replace("~1", "/").replace("~0", "~");
    }
}
