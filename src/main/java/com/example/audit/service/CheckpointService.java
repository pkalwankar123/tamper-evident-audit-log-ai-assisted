package com.example.audit.service;

import com.example.audit.api.ApiModels;
import com.example.audit.domain.AuditRecord;
import com.example.audit.domain.ChainCheckpoint;
import com.example.audit.repository.AuditRecordRepository;
import com.example.audit.repository.ChainCheckpointRepository;
import com.example.audit.security.AuditAccessPolicy;
import com.example.audit.security.AuthenticatedActor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * Creates and lists signed chain checkpoints.
 *
 * <p>A checkpoint is the answer to "the chain verifies, but is it the <em>same</em>
 * chain?". Internal link checking is satisfied by any well-formed chain, including one
 * an attacker rebuilt after deleting records. Signing (index, recordHash) at a point in
 * time gives verification an anchor outside the data being verified.
 *
 * <p>Admin-only and tenant-scoped, like every other privileged operation here.
 */
@Service
public class CheckpointService {
    private final AuditRecordRepository records;
    private final ChainCheckpointRepository checkpoints;
    private final SigningService signingService;
    private final AuditAccessPolicy accessPolicy;

    public CheckpointService(AuditRecordRepository records, ChainCheckpointRepository checkpoints,
                             SigningService signingService, AuditAccessPolicy accessPolicy) {
        this.records = records;
        this.checkpoints = checkpoints;
        this.signingService = signingService;
        this.accessPolicy = accessPolicy;
    }

    @Transactional
    public ApiModels.CheckpointResponse createCheckpoint(AuthenticatedActor actor) {
        accessPolicy.requireAdmin(actor, "create a chain checkpoint");
        List<AuditRecord> chain = records.findByTenantIdOrderByChainIndexAsc(actor.tenantId());
        if (chain.isEmpty()) {
            throw new IllegalArgumentException("Tenant '" + actor.tenantId()
                    + "' has no audit records to checkpoint");
        }
        AuditRecord tail = chain.get(chain.size() - 1);
        Instant createdAt = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        String payload = ChainCheckpoint.signingPayload(actor.tenantId(), tail.getChainIndex(),
                tail.getRecordHash(), createdAt);
        String keyId = signingService.keyId();
        ChainCheckpoint saved = checkpoints.save(new ChainCheckpoint(actor.tenantId(), tail.getChainIndex(),
                tail.getRecordHash(), createdAt, keyId, signingService.sign(payload)));
        return toResponse(saved);
    }

    @Transactional(readOnly = true)
    public List<ApiModels.CheckpointResponse> listCheckpoints(AuthenticatedActor actor) {
        accessPolicy.requireAdmin(actor, "list chain checkpoints");
        return checkpoints.findByTenantIdOrderByChainIndexAsc(actor.tenantId()).stream()
                .map(CheckpointService::toResponse)
                .toList();
    }

    private static ApiModels.CheckpointResponse toResponse(ChainCheckpoint checkpoint) {
        return new ApiModels.CheckpointResponse(checkpoint.getId(), checkpoint.getTenantId(),
                checkpoint.getChainIndex(), checkpoint.getRecordHash(), checkpoint.getCreatedAt(),
                checkpoint.getKeyId(), checkpoint.getSignatureBase64());
    }
}
