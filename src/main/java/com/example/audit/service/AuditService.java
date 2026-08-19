package com.example.audit.service;

import com.example.audit.api.ApiModels;
import com.example.audit.domain.AuditRecord;
import com.example.audit.domain.RedactionEntry;
import com.example.audit.repository.AuditRecordRepository;
import com.example.audit.repository.RedactionEntryRepository;
import com.example.audit.util.CanonicalJson;
import com.example.audit.util.Hashing;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.persistence.criteria.Predicate;
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

@Service
public class AuditService {
    public static final String GENESIS_HASH = "0".repeat(64);
    private static final String REDACTED = "[REDACTED]";

    private final AuditRecordRepository records;
    private final RedactionEntryRepository redactions;
    private final CanonicalJson canonicalJson;

    public AuditService(AuditRecordRepository records, RedactionEntryRepository redactions, CanonicalJson canonicalJson) {
        this.records = records;
        this.redactions = redactions;
        this.canonicalJson = canonicalJson;
    }

    @Transactional
    public synchronized ApiModels.AuditEventResponse append(ApiModels.CreateAuditEventRequest request) {
        // Truncate to millis so hash input matches DB Instant precision after round-trip.
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        Instant eventTime = (request.timestamp() == null ? now : request.timestamp()).truncatedTo(ChronoUnit.MILLIS);
        String payload = canonicalJson.write(request.payload());
        String payloadCommitment = Hashing.sha256(payload);
        Optional<AuditRecord> tail = records.lockTail();
        long index = tail.map(value -> value.getChainIndex() + 1).orElse(1L);
        String previousHash = tail.map(AuditRecord::getRecordHash).orElse(GENESIS_HASH);
        String recordHash = calculateRecordHash(index, request.eventType(), request.actorId(), request.resourceType(),
                request.resourceId(), eventTime, now, payloadCommitment, previousHash);
        AuditRecord record = new AuditRecord(index, request.eventType(), request.actorId(), request.resourceType(),
                request.resourceId(), eventTime, now, payload, payloadCommitment, previousHash, recordHash);
        return toResponse(records.saveAndFlush(record));
    }

    @Transactional(readOnly = true)
    public Page<ApiModels.AuditEventResponse> query(String actorId, String resourceType, String resourceId,
                                                     String eventType, Instant from, Instant to,
                                                     boolean includeArchived, Pageable pageable) {
        Specification<AuditRecord> specification = (root, query, builder) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (actorId != null) predicates.add(builder.equal(root.get("actorId"), actorId));
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

    @Transactional
    public ApiModels.RedactionResponse redact(UUID id, ApiModels.RedactionRequest request) {
        AuditRecord record = records.findById(id).orElseThrow(() -> new NoSuchElementException("Audit record not found"));
        JsonNode root = canonicalJson.read(record.getPayloadJson()).deepCopy();
        if (!(root instanceof ObjectNode objectNode)) {
            throw new IllegalArgumentException("Payload root must be a JSON object for structured redaction");
        }
        JsonNode target = objectNode.at(request.fieldPath());
        if (target.isMissingNode()) {
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
        String entryHash = calculateRedactionHash(id, sequence, request.fieldPath(), request.reason(), request.actorId(),
                createdAt, previousPayloadHash, newPayloadHash, previousEntryHash);
        redactions.save(new RedactionEntry(id, sequence, request.fieldPath(), request.reason(), request.actorId(),
                createdAt, previousPayloadHash, newPayloadHash, previousEntryHash, entryHash));
        record.setPayloadJson(newPayload);
        records.save(record);
        return new ApiModels.RedactionResponse(id, request.fieldPath(), REDACTED, entryHash);
    }

    @Transactional(readOnly = true)
    public ApiModels.VerificationResponse verify() {
        List<AuditRecord> all = records.findAllByOrderByChainIndexAsc();
        String expectedPrevious = GENESIS_HASH;
        long expectedIndex = 1;
        for (AuditRecord record : all) {
            if (record.getChainIndex() != expectedIndex) {
                return broken(record, "CHAIN_INDEX_GAP", "Expected chain index " + expectedIndex);
            }
            if (!Objects.equals(record.getPreviousHash(), expectedPrevious)) {
                return broken(record, "PREVIOUS_HASH_MISMATCH", "Record does not link to its predecessor");
            }
            String calculated = calculateRecordHash(record.getChainIndex(), record.getEventType(), record.getActorId(),
                    record.getResourceType(), record.getResourceId(), record.getTimestamp(), record.getIngestedAt(),
                    record.getPayloadCommitment(), record.getPreviousHash());
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
        return new ApiModels.VerificationResponse(true, (long) all.size(), null, null, null, "Chain is intact");
    }

    @Transactional
    public int archiveOlderThan(Instant cutoff) {
        List<AuditRecord> candidates = records.findByTimestampBeforeAndArchivedFalse(cutoff);
        candidates.forEach(record -> record.setArchived(true));
        records.saveAll(candidates);
        return candidates.size();
    }

    @Transactional(readOnly = true)
    public List<AuditRecord> allRecords() {
        return records.findAllByOrderByChainIndexAsc();
    }

    public ApiModels.AuditEventResponse toResponse(AuditRecord record) {
        return new ApiModels.AuditEventResponse(record.getId(), record.getChainIndex(), record.getEventType(),
                record.getActorId(), record.getResourceType(), record.getResourceId(),
                canonicalJson.read(record.getPayloadJson()), record.getTimestamp(), record.getIngestedAt(),
                record.getPayloadCommitment(), record.getPreviousHash(), record.getRecordHash(), record.isArchived());
    }

    private String verifyPayloadAndRedactions(AuditRecord record) {
        List<RedactionEntry> entries = redactions.findByRecordIdOrderBySequenceNumberAsc(record.getId());
        String currentPayloadHash = Hashing.sha256(record.getPayloadJson());
        if (entries.isEmpty()) {
            return currentPayloadHash.equals(record.getPayloadCommitment()) ? null : "Payload changed without a redaction entry";
        }
        String expectedPayloadHash = record.getPayloadCommitment();
        String expectedPreviousEntry = GENESIS_HASH;
        long expectedSequence = 1;
        for (RedactionEntry entry : entries) {
            if (entry.getSequenceNumber() != expectedSequence) return "Redaction sequence is not contiguous";
            if (!entry.getPreviousEntryHash().equals(expectedPreviousEntry)) return "Redaction entry link is invalid";
            if (!entry.getPreviousPayloadHash().equals(expectedPayloadHash)) return "Redaction payload transition is invalid";
            String calculated = calculateRedactionHash(entry.getRecordId(), entry.getSequenceNumber(), entry.getFieldPath(),
                    entry.getReason(), entry.getActorId(), entry.getCreatedAt(), entry.getPreviousPayloadHash(),
                    entry.getNewPayloadHash(), entry.getPreviousEntryHash());
            if (!calculated.equals(entry.getEntryHash())) return "Redaction entry hash is invalid";
            expectedPayloadHash = entry.getNewPayloadHash();
            expectedPreviousEntry = entry.getEntryHash();
            expectedSequence++;
        }
        return currentPayloadHash.equals(expectedPayloadHash) ? null : "Current payload does not match the latest authorized redaction";
    }

    private ApiModels.VerificationResponse broken(AuditRecord record, String type, String details) {
        return new ApiModels.VerificationResponse(false, record.getChainIndex() - 1, record.getId(),
                record.getChainIndex(), type, details);
    }

    private static String calculateRecordHash(long index, String eventType, String actorId, String resourceType,
                                              String resourceId, Instant timestamp, Instant ingestedAt,
                                              String payloadCommitment, String previousHash) {
        return Hashing.sha256(String.join("|", Long.toString(index), eventType, actorId, resourceType, resourceId,
                timestamp.toString(), ingestedAt.toString(), payloadCommitment, previousHash));
    }

    private static String calculateRedactionHash(UUID recordId, long sequence, String fieldPath, String reason,
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
            String key = unescape(parts[i]);
            current = current.get(key);
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
