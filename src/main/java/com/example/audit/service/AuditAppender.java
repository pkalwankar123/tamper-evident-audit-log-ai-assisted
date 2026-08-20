package com.example.audit.service;

import com.example.audit.config.AuditProperties;
import com.example.audit.domain.AuditRecord;
import com.example.audit.domain.ChainHead;
import com.example.audit.domain.IdempotencyRecord;
import com.example.audit.repository.AuditRecordRepository;
import com.example.audit.repository.ChainHeadRepository;
import com.example.audit.repository.IdempotencyRecordRepository;
import com.example.audit.security.AuthenticatedActor;
import com.example.audit.util.Hashing;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * The single transactional unit that extends a tenant chain by one record.
 *
 * <p>Everything that must succeed or fail together lives here: taking the chain-head
 * lock, computing the link, inserting the record, advancing the head, and reserving the
 * idempotency key. If any step fails, all of them roll back - so a failed append leaves
 * no consumed index, no dangling head, and no burned idempotency key. That is what
 * {@code AppendRollbackTest} asserts.
 *
 * <p>Serialization is the database row lock on {@link ChainHead}, not an in-process
 * monitor. The previous {@code synchronized} on the service method was doubly wrong: it
 * did nothing across nodes, and because Spring wraps the method in a transactional
 * proxy the lock was released before the transaction committed, so even single-node
 * writers could interleave between hash computation and commit.
 */
@Service
public class AuditAppender {
    private final AuditRecordRepository records;
    private final ChainHeadRepository chainHeads;
    private final IdempotencyRecordRepository idempotencyRecords;
    private final AuditProperties properties;

    public AuditAppender(AuditRecordRepository records, ChainHeadRepository chainHeads,
                         IdempotencyRecordRepository idempotencyRecords, AuditProperties properties) {
        this.records = records;
        this.chainHeads = chainHeads;
        this.idempotencyRecords = idempotencyRecords;
        this.properties = properties;
    }

    @Transactional
    public AuditRecord append(AuthenticatedActor actor, String eventType, String resourceType, String resourceId,
                              Instant eventTime, String canonicalPayload, String idempotencyKey,
                              String requestHash) {
        int payloadBytes = canonicalPayload.getBytes(StandardCharsets.UTF_8).length;
        if (payloadBytes > properties.getPayload().getMaxBytes()) {
            throw new PayloadTooLargeException("Payload of " + payloadBytes + " bytes exceeds the "
                    + properties.getPayload().getMaxBytes() + " byte limit (audit.payload.max-bytes)");
        }

        ChainHead head = chainHeads.lockByTenantId(actor.tenantId())
                .orElseThrow(() -> new IllegalStateException(
                        "Chain head for tenant '" + actor.tenantId() + "' was not initialised"));

        Instant ingestedAt = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        long index = head.getLastIndex() + 1;
        String previousHash = head.getLastHash();
        String payloadCommitment = Hashing.sha256(canonicalPayload);
        String recordHash = AuditService.calculateRecordHash(actor.tenantId(), index, eventType, actor.actorId(),
                resourceType, resourceId, eventTime, ingestedAt, payloadCommitment, previousHash);

        AuditRecord record = new AuditRecord(actor.tenantId(), index, eventType, actor.actorId(), resourceType,
                resourceId, eventTime, ingestedAt, canonicalPayload, payloadCommitment, previousHash, recordHash);
        AuditRecord saved = records.saveAndFlush(record);

        head.advance(index, recordHash);
        chainHeads.saveAndFlush(head);

        if (idempotencyKey != null && !idempotencyKey.isBlank()) {
            // Unique (tenant, key) - a concurrent duplicate loses here and the whole
            // append rolls back, leaving the winner's single record in the chain.
            idempotencyRecords.saveAndFlush(new IdempotencyRecord(actor.tenantId(), idempotencyKey, requestHash,
                    saved.getId(), Instant.now().truncatedTo(ChronoUnit.MILLIS)));
        }
        return saved;
    }
}
