package com.example.audit.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * A signed commitment to the state of a tenant chain at a point in time.
 *
 * <p>Hash chaining alone detects edits and reordering, but it cannot detect a
 * <em>consistent</em> rewrite: an attacker with database write access can delete the
 * last N records, or rebuild the entire chain from scratch, and the result still
 * verifies internally because every link was recomputed. A checkpoint closes that hole.
 * It records (chainIndex, recordHash) signed with the service key, so verification can
 * assert that the chain still contains the exact record the service previously attested
 * to at that index. Truncation and wholesale rewrites both fail that check.
 *
 * <p>Checkpoints are append-only and admin-created; see {@code CheckpointService}.
 */
@Entity
@Table(name = "chain_checkpoints",
        indexes = @Index(name = "idx_checkpoint_tenant", columnList = "tenant_id,chain_index"))
public class ChainCheckpoint {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "tenant_id", nullable = false, updatable = false, length = 200)
    private String tenantId;

    @Column(name = "chain_index", nullable = false, updatable = false)
    private long chainIndex;

    @Column(name = "record_hash", nullable = false, updatable = false, length = 64)
    private String recordHash;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "key_id", nullable = false, updatable = false, length = 200)
    private String keyId;

    @Column(name = "signature_base64", nullable = false, updatable = false, length = 512)
    private String signatureBase64;

    protected ChainCheckpoint() {
    }

    public ChainCheckpoint(String tenantId, long chainIndex, String recordHash, Instant createdAt,
                           String keyId, String signatureBase64) {
        this.tenantId = tenantId;
        this.chainIndex = chainIndex;
        this.recordHash = recordHash;
        this.createdAt = createdAt;
        this.keyId = keyId;
        this.signatureBase64 = signatureBase64;
    }

    public UUID getId() { return id; }
    public String getTenantId() { return tenantId; }
    public long getChainIndex() { return chainIndex; }
    public String getRecordHash() { return recordHash; }
    public Instant getCreatedAt() { return createdAt; }
    public String getKeyId() { return keyId; }
    public String getSignatureBase64() { return signatureBase64; }

    /** The exact bytes covered by the signature - reproducible by any verifier. */
    public String signingPayload() {
        return signingPayload(tenantId, chainIndex, recordHash, createdAt);
    }

    public static String signingPayload(String tenantId, long chainIndex, String recordHash, Instant createdAt) {
        return String.join("|", "checkpoint-v1", tenantId, Long.toString(chainIndex), recordHash,
                createdAt.toString());
    }
}
