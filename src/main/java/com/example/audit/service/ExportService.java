package com.example.audit.service;

import com.example.audit.api.ApiModels;
import com.example.audit.domain.AuditRecord;
import com.example.audit.security.AuditAccessPolicy;
import com.example.audit.security.AuthenticatedActor;
import com.example.audit.util.Hashing;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Produces a signed, self-contained evidence bundle.
 *
 * <p>Ownership rules are the same as everywhere else and are applied here, not only at
 * the controller: export requires {@code ROLE_AUDIT_ADMIN}, and the selection is
 * confined to the caller's own tenant. Asking to export another tenant is not an empty
 * result, it is a denial.
 *
 * <p>The bundle spans the contiguous chain-index range covering the selection, with
 * non-matching records inside that range included and flagged {@code selected=false}.
 * That is not padding: without the intervening records a recipient cannot check the
 * hash links between the selected ones, and the chain evidence would be unverifiable.
 * Each record carries its redaction ledger, so payload-vs-commitment differences can be
 * explained offline rather than taken on trust.
 */
@Service
public class ExportService {
    private static final String BUNDLE_VERSION = "2.0";

    private final AuditService auditService;
    private final SigningService signingService;
    private final AuditAccessPolicy accessPolicy;

    public ExportService(AuditService auditService, SigningService signingService,
                         AuditAccessPolicy accessPolicy) {
        this.auditService = auditService;
        this.signingService = signingService;
        this.accessPolicy = accessPolicy;
    }

    @Transactional(readOnly = true)
    public ApiModels.ExportManifest export(AuthenticatedActor actor, String actorId, String resourceId) {
        accessPolicy.requireAdmin(actor, "export an audit bundle");
        if ((actorId == null) == (resourceId == null)) {
            throw new IllegalArgumentException("Provide exactly one of actorId or resourceId");
        }

        List<AuditRecord> all = auditService.tenantRecords(actor);
        List<AuditRecord> selected = all.stream()
                .filter(record -> actorId != null
                        ? actorId.equals(record.getActorId())
                        : resourceId.equals(record.getResourceId()))
                .toList();
        if (selected.isEmpty()) {
            throw new java.util.NoSuchElementException(
                    "No records in tenant '" + actor.tenantId() + "' matched the export selection");
        }

        long min = selected.get(0).getChainIndex();
        long max = selected.get(selected.size() - 1).getChainIndex();
        Set<UUID> selectedIds = new HashSet<>();
        selected.forEach(record -> selectedIds.add(record.getId()));

        List<ApiModels.ExportRecord> segment = new ArrayList<>();
        for (AuditRecord record : all) {
            if (record.getChainIndex() >= min && record.getChainIndex() <= max) {
                segment.add(new ApiModels.ExportRecord(auditService.toResponse(record),
                        selectedIds.contains(record.getId()), auditService.redactionViews(record.getId())));
            }
        }

        String selectionType = actorId != null ? "actorId" : "resourceId";
        String selectionValue = actorId != null ? actorId : resourceId;
        Instant generatedAt = Instant.now();
        String keyId = signingService.keyId();
        String canonical = ExportCanonicalForm.serialize(BUNDLE_VERSION, generatedAt, actor.tenantId(),
                selectionType, selectionValue, keyId, segment);
        String manifestHash = Hashing.sha256(canonical);
        return new ApiModels.ExportManifest(BUNDLE_VERSION, generatedAt, actor.tenantId(), selectionType,
                selectionValue, keyId, signingService.publicKeyBase64(), manifestHash,
                signingService.sign(manifestHash), segment);
    }
}
