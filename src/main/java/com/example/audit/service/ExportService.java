package com.example.audit.service;

import com.example.audit.api.ApiModels;
import com.example.audit.domain.AuditRecord;
import com.example.audit.util.Hashing;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

@Service
public class ExportService {
    private final AuditService auditService;
    private final SigningService signingService;
    private final ObjectMapper mapper;

    public ExportService(AuditService auditService, SigningService signingService, ObjectMapper mapper) {
        this.auditService = auditService;
        this.signingService = signingService;
        this.mapper = mapper.copy().configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
    }

    @Transactional(readOnly = true)
    public ApiModels.ExportManifest export(String actorId, String resourceId) {
        if ((actorId == null) == (resourceId == null)) {
            throw new IllegalArgumentException("Provide exactly one of actorId or resourceId");
        }
        List<AuditRecord> all = auditService.allRecords();
        List<AuditRecord> selected = all.stream()
                .filter(record -> actorId != null ? actorId.equals(record.getActorId()) : resourceId.equals(record.getResourceId()))
                .sorted(Comparator.comparingLong(AuditRecord::getChainIndex))
                .toList();
        if (selected.isEmpty()) {
            throw new IllegalArgumentException("No records matched the export selection");
        }
        long min = selected.getFirst().getChainIndex();
        long max = selected.getLast().getChainIndex();
        List<ApiModels.ExportRecord> segment = new ArrayList<>();
        for (AuditRecord record : all) {
            if (record.getChainIndex() >= min && record.getChainIndex() <= max) {
                boolean isSelected = selected.stream().anyMatch(item -> item.getId().equals(record.getId()));
                segment.add(new ApiModels.ExportRecord(auditService.toResponse(record), isSelected));
            }
        }
        String selectionType = actorId != null ? "actorId" : "resourceId";
        String selectionValue = actorId != null ? actorId : resourceId;
        Instant generatedAt = Instant.now();
        String unsigned = serializeUnsigned(generatedAt, selectionType, selectionValue, segment);
        String manifestHash = Hashing.sha256(unsigned);
        return new ApiModels.ExportManifest("1.0", generatedAt, selectionType, selectionValue,
                signingService.keyId(), signingService.publicKeyBase64(), manifestHash,
                signingService.sign(manifestHash), segment);
    }

    private String serializeUnsigned(Instant generatedAt, String selectionType, String selectionValue,
                                     List<ApiModels.ExportRecord> records) {
        try {
            return mapper.writeValueAsString(new UnsignedManifest("1.0", generatedAt, selectionType, selectionValue,
                    signingService.keyId(), records));
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Unable to serialize export manifest", exception);
        }
    }

    private record UnsignedManifest(String bundleVersion, Instant generatedAt, String selectionType,
                                    String selectionValue, String keyId, List<ApiModels.ExportRecord> records) {
    }
}
