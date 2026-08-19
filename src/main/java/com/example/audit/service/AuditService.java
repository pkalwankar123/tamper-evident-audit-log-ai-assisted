package com.example.audit.service;

import com.example.audit.api.ApiModels;
import com.example.audit.domain.AuditRecord;
import com.example.audit.repository.AuditRecordRepository;
import com.example.audit.util.CanonicalJson;
import com.example.audit.util.Hashing;
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
import java.util.Objects;
import java.util.Optional;

@Service
public class AuditService {
    public static final String GENESIS_HASH = "0".repeat(64);

    private final AuditRecordRepository records;
    private final CanonicalJson canonicalJson;

    public AuditService(AuditRecordRepository records, CanonicalJson canonicalJson) {
        this.records = records;
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
            String payloadProblem = verifyPayload(record);
            if (payloadProblem != null) {
                return broken(record, "PAYLOAD_MISMATCH", payloadProblem);
            }
            expectedPrevious = record.getRecordHash();
            expectedIndex++;
        }
        return new ApiModels.VerificationResponse(true, (long) all.size(), null, null, null, "Chain is intact");
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

    private String verifyPayload(AuditRecord record) {
        String currentPayloadHash = Hashing.sha256(record.getPayloadJson());
        return currentPayloadHash.equals(record.getPayloadCommitment()) ? null : "Payload changed unexpectedly";
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
}
