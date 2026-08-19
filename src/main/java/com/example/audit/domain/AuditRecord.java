package com.example.audit.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "audit_records",
        uniqueConstraints = @UniqueConstraint(name = "uk_audit_chain_index", columnNames = "chain_index"),
        indexes = {
                @Index(name = "idx_audit_actor", columnList = "actor_id"),
                @Index(name = "idx_audit_resource", columnList = "resource_type,resource_id"),
                @Index(name = "idx_audit_event_type", columnList = "event_type"),
                @Index(name = "idx_audit_timestamp", columnList = "event_timestamp")
        })
public class AuditRecord {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "chain_index", nullable = false, updatable = false)
    private long chainIndex;

    @Column(name = "event_type", nullable = false, updatable = false, length = 120)
    private String eventType;

    @Column(name = "actor_id", nullable = false, updatable = false, length = 200)
    private String actorId;

    @Column(name = "resource_type", nullable = false, updatable = false, length = 120)
    private String resourceType;

    @Column(name = "resource_id", nullable = false, updatable = false, length = 200)
    private String resourceId;

    @Column(name = "event_timestamp", nullable = false, updatable = false)
    private Instant timestamp;

    @Column(name = "ingested_at", nullable = false, updatable = false)
    private Instant ingestedAt;

    @Lob
    @Column(name = "payload_json", nullable = false)
    private String payloadJson;

    @Column(name = "payload_commitment", nullable = false, updatable = false, length = 64)
    private String payloadCommitment;

    @Column(name = "previous_hash", nullable = false, updatable = false, length = 64)
    private String previousHash;

    @Column(name = "record_hash", nullable = false, updatable = false, length = 64)
    private String recordHash;

    @Column(nullable = false)
    private boolean archived;

    protected AuditRecord() {
    }

    public AuditRecord(long chainIndex, String eventType, String actorId, String resourceType,
                       String resourceId, Instant timestamp, Instant ingestedAt, String payloadJson,
                       String payloadCommitment, String previousHash, String recordHash) {
        this.chainIndex = chainIndex;
        this.eventType = eventType;
        this.actorId = actorId;
        this.resourceType = resourceType;
        this.resourceId = resourceId;
        this.timestamp = timestamp;
        this.ingestedAt = ingestedAt;
        this.payloadJson = payloadJson;
        this.payloadCommitment = payloadCommitment;
        this.previousHash = previousHash;
        this.recordHash = recordHash;
        this.archived = false;
    }

    public UUID getId() { return id; }
    public long getChainIndex() { return chainIndex; }
    public String getEventType() { return eventType; }
    public String getActorId() { return actorId; }
    public String getResourceType() { return resourceType; }
    public String getResourceId() { return resourceId; }
    public Instant getTimestamp() { return timestamp; }
    public Instant getIngestedAt() { return ingestedAt; }
    public String getPayloadJson() { return payloadJson; }
    public String getPayloadCommitment() { return payloadCommitment; }
    public String getPreviousHash() { return previousHash; }
    public String getRecordHash() { return recordHash; }
    public boolean isArchived() { return archived; }
    public void setPayloadJson(String payloadJson) { this.payloadJson = payloadJson; }
    public void setArchived(boolean archived) { this.archived = archived; }
}
