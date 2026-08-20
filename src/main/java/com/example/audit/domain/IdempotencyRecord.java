package com.example.audit.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

import java.time.Instant;
import java.util.UUID;

/**
 * Durable replay protection for appends.
 *
 * <p>Stored in the database rather than in a per-node cache, so a retried request is
 * still recognised as a replay after a restart or when it lands on a different node.
 * The unique constraint on (tenant, key) is what actually enforces single-use under
 * concurrency: two simultaneous retries race to insert and exactly one wins, the loser
 * is served the winner's record.
 *
 * <p>{@code requestHash} is retained so that reusing a key with a <em>different</em>
 * body is rejected as a conflict rather than silently returning an unrelated record -
 * that would let a caller mask a real event behind an earlier key.
 */
@Entity
@Table(name = "idempotency_records",
        uniqueConstraints = @UniqueConstraint(name = "uk_idempotency_tenant_key",
                columnNames = {"tenant_id", "idempotency_key"}))
public class IdempotencyRecord {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "tenant_id", nullable = false, updatable = false, length = 200)
    private String tenantId;

    @Column(name = "idempotency_key", nullable = false, updatable = false, length = 200)
    private String idempotencyKey;

    @Column(name = "request_hash", nullable = false, updatable = false, length = 64)
    private String requestHash;

    @Column(name = "record_id", nullable = false, updatable = false)
    private UUID recordId;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected IdempotencyRecord() {
    }

    public IdempotencyRecord(String tenantId, String idempotencyKey, String requestHash, UUID recordId,
                             Instant createdAt) {
        this.tenantId = tenantId;
        this.idempotencyKey = idempotencyKey;
        this.requestHash = requestHash;
        this.recordId = recordId;
        this.createdAt = createdAt;
    }

    public UUID getId() { return id; }
    public String getTenantId() { return tenantId; }
    public String getIdempotencyKey() { return idempotencyKey; }
    public String getRequestHash() { return requestHash; }
    public UUID getRecordId() { return recordId; }
    public Instant getCreatedAt() { return createdAt; }
}
