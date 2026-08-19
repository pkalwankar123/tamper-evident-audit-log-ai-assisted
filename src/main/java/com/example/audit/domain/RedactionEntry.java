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

@Entity
@Table(name = "redaction_entries", indexes = @Index(name = "idx_redaction_record", columnList = "record_id,sequence_number"))
public class RedactionEntry {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "record_id", nullable = false, updatable = false)
    private UUID recordId;

    @Column(name = "sequence_number", nullable = false, updatable = false)
    private long sequenceNumber;

    @Column(name = "field_path", nullable = false, updatable = false, length = 500)
    private String fieldPath;

    @Column(nullable = false, updatable = false, length = 500)
    private String reason;

    @Column(name = "actor_id", nullable = false, updatable = false, length = 200)
    private String actorId;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "previous_payload_hash", nullable = false, updatable = false, length = 64)
    private String previousPayloadHash;

    @Column(name = "new_payload_hash", nullable = false, updatable = false, length = 64)
    private String newPayloadHash;

    @Column(name = "previous_entry_hash", nullable = false, updatable = false, length = 64)
    private String previousEntryHash;

    @Column(name = "entry_hash", nullable = false, updatable = false, length = 64)
    private String entryHash;

    protected RedactionEntry() {
    }

    public RedactionEntry(UUID recordId, long sequenceNumber, String fieldPath, String reason, String actorId,
                          Instant createdAt, String previousPayloadHash, String newPayloadHash,
                          String previousEntryHash, String entryHash) {
        this.recordId = recordId;
        this.sequenceNumber = sequenceNumber;
        this.fieldPath = fieldPath;
        this.reason = reason;
        this.actorId = actorId;
        this.createdAt = createdAt;
        this.previousPayloadHash = previousPayloadHash;
        this.newPayloadHash = newPayloadHash;
        this.previousEntryHash = previousEntryHash;
        this.entryHash = entryHash;
    }

    public UUID getId() { return id; }
    public UUID getRecordId() { return recordId; }
    public long getSequenceNumber() { return sequenceNumber; }
    public String getFieldPath() { return fieldPath; }
    public String getReason() { return reason; }
    public String getActorId() { return actorId; }
    public Instant getCreatedAt() { return createdAt; }
    public String getPreviousPayloadHash() { return previousPayloadHash; }
    public String getNewPayloadHash() { return newPayloadHash; }
    public String getPreviousEntryHash() { return previousEntryHash; }
    public String getEntryHash() { return entryHash; }
}
