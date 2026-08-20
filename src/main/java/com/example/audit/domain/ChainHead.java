package com.example.audit.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * The serialization point for appends, one row per tenant.
 *
 * <p>This exists to replace the previous in-process {@code synchronized} block, which
 * only serialized writers inside a single JVM and therefore provided no protection at
 * all once the service runs on more than one node. Every append takes a
 * {@code PESSIMISTIC_WRITE} lock on this row for its tenant, so the database - the one
 * component genuinely shared by every node - is what orders concurrent appends.
 *
 * <p>The head is advanced inside the same transaction that inserts the record, so a
 * rolled-back append leaves no gap: the head still points at the last committed record
 * and the next append reuses the index. The previous design read the tail with a
 * separate query, which could hand the same index to two transactions whenever the
 * table was empty (no row existed to lock).
 */
@Entity
@Table(name = "chain_heads")
public class ChainHead {
    @Id
    @Column(name = "tenant_id", nullable = false, updatable = false, length = 200)
    private String tenantId;

    @Column(name = "last_index", nullable = false)
    private long lastIndex;

    @Column(name = "last_hash", nullable = false, length = 64)
    private String lastHash;

    protected ChainHead() {
    }

    public ChainHead(String tenantId, long lastIndex, String lastHash) {
        this.tenantId = tenantId;
        this.lastIndex = lastIndex;
        this.lastHash = lastHash;
    }

    public String getTenantId() { return tenantId; }
    public long getLastIndex() { return lastIndex; }
    public String getLastHash() { return lastHash; }

    public void advance(long index, String hash) {
        this.lastIndex = index;
        this.lastHash = hash;
    }
}
