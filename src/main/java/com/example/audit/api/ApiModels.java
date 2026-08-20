package com.example.audit.api;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public final class ApiModels {
    private ApiModels() {
    }

    /**
     * Note what is <em>absent</em>: {@code actorId} and {@code tenantId}. Both used to be
     * caller-supplied and are now derived from the authenticated principal, so there is
     * no field for a caller to lie in. Submitting them is not "rejected" - the concept
     * simply no longer exists at the API boundary.
     */
    public record CreateAuditEventRequest(
            @NotBlank @Size(max = 120) String eventType,
            @NotBlank @Size(max = 120) String resourceType,
            @NotBlank @Size(max = 200) String resourceId,
            @NotNull JsonNode payload,
            Instant timestamp) {
    }

    public record AuditEventResponse(
            UUID id,
            String tenantId,
            long chainIndex,
            String eventType,
            String actorId,
            String resourceType,
            String resourceId,
            JsonNode payload,
            Instant timestamp,
            Instant ingestedAt,
            String payloadCommitment,
            String previousHash,
            String recordHash,
            boolean archived) {
    }

    /** Carries whether the append was a genuine write or a replay of an earlier one. */
    public record AppendOutcome(AuditEventResponse event, boolean replayed) {
    }

    /** The redacting actor is taken from the principal, not from the body. */
    public record RedactionRequest(
            @NotBlank @Size(max = 500) String fieldPath,
            @NotBlank @Size(max = 500) String reason) {
    }

    public record RedactionResponse(UUID recordId, String fieldPath, String replacement, String redactionEntryHash) {
    }

    /**
     * A redaction ledger entry as exported. Present in the bundle so a recipient can
     * replay the payload transitions offline instead of having to trust that a payload
     * differing from its original commitment was redacted legitimately.
     */
    public record RedactionEntryView(
            long sequenceNumber,
            String fieldPath,
            String reason,
            String actorId,
            Instant createdAt,
            String previousPayloadHash,
            String newPayloadHash,
            String previousEntryHash,
            String entryHash) {
    }

    public record VerificationResponse(
            boolean intact,
            Long checkedRecords,
            UUID firstInconsistentRecordId,
            Long firstInconsistentChainIndex,
            String violationType,
            String details) {
    }

    public record ExportRecord(AuditEventResponse event, boolean selected, List<RedactionEntryView> redactions) {
    }

    public record ExportManifest(
            String bundleVersion,
            Instant generatedAt,
            String tenantId,
            String selectionType,
            String selectionValue,
            String keyId,
            String publicKeyBase64,
            String manifestHash,
            String signatureBase64,
            List<ExportRecord> records) {
    }

    public record CheckpointResponse(
            UUID id,
            String tenantId,
            long chainIndex,
            String recordHash,
            Instant createdAt,
            String keyId,
            String signatureBase64) {
    }

    public record ArchiveResponse(int archivedCount, String tenantId, Instant ranAt, boolean chainStillIntact) {
    }
}
