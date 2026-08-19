package com.example.audit.api;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;
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

    public record VerificationResponse(
            boolean intact,
            Long checkedRecords,
            UUID firstInconsistentRecordId,
            Long firstInconsistentChainIndex,
            String violationType,
            String details) {
    }
}
