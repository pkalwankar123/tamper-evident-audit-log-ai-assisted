package com.example.audit.api;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public final class ApiModels {
    private ApiModels() {
    }

    public record CreateAuditEventRequest(
            @NotBlank String eventType,
            @NotBlank String actorId,
            @NotBlank String resourceType,
            @NotBlank String resourceId,
            @NotNull JsonNode payload,
            Instant timestamp) {
    }

    public record AuditEventResponse(
            UUID id,
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

    public record RedactionRequest(
            @NotBlank String fieldPath,
            @NotBlank String reason,
            @NotBlank String actorId) {
    }

    public record RedactionResponse(UUID recordId, String fieldPath, String replacement, String redactionEntryHash) {
    }

    public record VerificationResponse(
            boolean intact,
            Long checkedRecords,
            UUID firstInconsistentRecordId,
            Long firstInconsistentChainIndex,
            String violationType,
            String details) {
    }

    public record ExportRecord(AuditEventResponse event, boolean selected) {
    }

    public record ExportManifest(
            String bundleVersion,
            Instant generatedAt,
            String selectionType,
            String selectionValue,
            String keyId,
            String publicKeyBase64,
            String manifestHash,
            String signatureBase64,
            List<ExportRecord> records) {
    }
}
