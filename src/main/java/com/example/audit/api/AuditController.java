package com.example.audit.api;

import com.example.audit.security.ActorResolver;
import com.example.audit.security.AuthenticatedActor;
import com.example.audit.service.AuditService;
import com.example.audit.service.CheckpointService;
import com.example.audit.service.ExportService;
import com.example.audit.service.RetentionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Size;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * The HTTP surface.
 *
 * <p>Note that no endpoint accepts an {@code actorId} or {@code tenantId} for the
 * purposes of a security decision. Both are resolved from the authenticated principal
 * by {@link ActorResolver} and passed down as an {@link AuthenticatedActor}. The one
 * remaining {@code actorId} query parameter, on read and export, is a <em>filter</em>
 * within data the caller may already see - the service re-checks it against the policy
 * and denies rather than widening scope.
 *
 * <p>Authorization is enforced in the service layer, not here. The role rules in
 * {@code SecurityConfig} are a coarse first gate; the binding decisions live next to the
 * data so they cannot be bypassed by a future caller that is not this controller.
 */
@RestController
@RequestMapping("/audit")
@Validated
@Tag(name = "Audit Log", description = "Append, query, verify, redact, checkpoint, archive and export audit events")
public class AuditController {
    private static final int MAX_PAGE_SIZE = 500;

    private final AuditService auditService;
    private final ExportService exportService;
    private final RetentionService retentionService;
    private final CheckpointService checkpointService;
    private final ActorResolver actorResolver;

    public AuditController(AuditService auditService, ExportService exportService,
                           RetentionService retentionService, CheckpointService checkpointService,
                           ActorResolver actorResolver) {
        this.auditService = auditService;
        this.exportService = exportService;
        this.retentionService = retentionService;
        this.checkpointService = checkpointService;
        this.actorResolver = actorResolver;
    }

    @PostMapping
    @Operation(summary = "Append an audit event",
            description = "Appends to the calling tenant's hash chain. The actor and tenant recorded are "
                    + "derived from the authenticated principal - they cannot be supplied by the caller. "
                    + "Supply an Idempotency-Key header to make retries safe: a replay returns the original "
                    + "record with 200 instead of appending a duplicate.")
    public ResponseEntity<ApiModels.AuditEventResponse> append(
            @Valid @RequestBody ApiModels.CreateAuditEventRequest request,
            @RequestHeader(name = "Idempotency-Key", required = false)
            @Size(max = 200, message = "Idempotency-Key must be at most 200 characters") String idempotencyKey,
            Authentication authentication) {
        AuthenticatedActor actor = actorResolver.resolve(authentication);
        ApiModels.AppendOutcome outcome = auditService.append(actor, request, idempotencyKey);
        return ResponseEntity
                .status(outcome.replayed() ? HttpStatus.OK : HttpStatus.CREATED)
                .header("Idempotent-Replay", Boolean.toString(outcome.replayed()))
                .body(outcome.event());
    }

    @GetMapping
    @Operation(summary = "Query audit events",
            description = "Always confined to the caller's tenant. Non-admin callers are additionally "
                    + "confined to their own actorId; asking for another actor is denied, not silently "
                    + "rewritten.")
    public Page<ApiModels.AuditEventResponse> query(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceType,
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @RequestParam(defaultValue = "false") boolean includeArchived,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            Authentication authentication) {
        validatePagination(page, size, from, to);
        AuthenticatedActor actor = actorResolver.resolve(authentication);
        return auditService.query(actor, actorId, resourceType, resourceId, eventType, from, to, includeArchived,
                PageRequest.of(page, size, Sort.by("chainIndex").ascending()));
    }

    @GetMapping("/{id}")
    @Operation(summary = "Fetch a single audit event",
            description = "Denied for records outside the caller's tenant, or owned by another actor when "
                    + "the caller is not an administrator.")
    public ApiModels.AuditEventResponse findById(@PathVariable UUID id, Authentication authentication) {
        return auditService.findById(actorResolver.resolve(authentication), id);
    }

    @GetMapping("/verify")
    @Operation(summary = "Verify the tenant hash chain",
            description = "Recomputes the caller's tenant chain, including archived records, replays the "
                    + "redaction ledger, and checks every signed checkpoint. Returns intact=false with a "
                    + "violation type on tamper.")
    public ApiModels.VerificationResponse verify(Authentication authentication) {
        return auditService.verify(actorResolver.resolve(authentication));
    }

    @PostMapping("/{id}/redact")
    @Operation(summary = "Redact a payload field",
            description = "Admin-only, tenant-scoped. The redacting actor is taken from the principal and "
                    + "written into the redaction ledger, which keeps the chain verifiable.")
    public ApiModels.RedactionResponse redact(@PathVariable UUID id,
                                              @Valid @RequestBody ApiModels.RedactionRequest request,
                                              Authentication authentication) {
        return auditService.redact(actorResolver.resolve(authentication), id, request);
    }

    @GetMapping("/export")
    @Operation(summary = "Export a signed, independently verifiable bundle",
            description = "Admin-only and confined to the caller's tenant. The bundle contains the "
                    + "contiguous chain segment plus each record's redaction ledger, so a recipient can "
                    + "re-derive every hash and check the Ed25519 signature offline.")
    public ApiModels.ExportManifest export(@RequestParam(required = false) String actorId,
                                           @RequestParam(required = false) String resourceId,
                                           Authentication authentication) {
        return exportService.export(actorResolver.resolve(authentication), actorId, resourceId);
    }

    @PostMapping("/retention/run")
    @Operation(summary = "Run the retention sweep on demand",
            description = "Admin-only, scoped to the caller's tenant. Archives records older than "
                    + "audit.retention.days. Archiving never deletes and never alters hashed fields.")
    public ApiModels.ArchiveResponse runRetention(Authentication authentication) {
        AuthenticatedActor actor = actorResolver.resolve(authentication);
        int archived = retentionService.applyRetentionPolicy(actor);
        return archiveResponse(actor, archived);
    }

    @PostMapping("/archive")
    @Operation(summary = "Archive records older than a given age",
            description = "Admin-only, scoped to the caller's tenant. The response reports whether the "
                    + "chain still verifies afterwards, so archiving can never quietly damage integrity.")
    public ApiModels.ArchiveResponse archive(@RequestParam(defaultValue = "365") int olderThanDays,
                                             Authentication authentication) {
        AuthenticatedActor actor = actorResolver.resolve(authentication);
        int archived = retentionService.archiveOlderThanDays(actor, olderThanDays);
        return archiveResponse(actor, archived);
    }

    @PostMapping("/checkpoints")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Create a signed chain checkpoint",
            description = "Admin-only. Signs (chainIndex, recordHash) for the tenant head so later "
                    + "verification can detect truncation or a wholesale chain rewrite, which link "
                    + "checking alone cannot.")
    public ApiModels.CheckpointResponse createCheckpoint(Authentication authentication) {
        return checkpointService.createCheckpoint(actorResolver.resolve(authentication));
    }

    @GetMapping("/checkpoints")
    @Operation(summary = "List signed chain checkpoints", description = "Admin-only, tenant-scoped.")
    public List<ApiModels.CheckpointResponse> listCheckpoints(Authentication authentication) {
        return checkpointService.listCheckpoints(actorResolver.resolve(authentication));
    }

    private ApiModels.ArchiveResponse archiveResponse(AuthenticatedActor actor, int archived) {
        boolean intact = auditService.verify(actor).intact();
        return new ApiModels.ArchiveResponse(archived, actor.tenantId(), Instant.now(), intact);
    }

    private void validatePagination(int page, int size, Instant from, Instant to) {
        if (page < 0) {
            throw new IllegalArgumentException("page must be >= 0");
        }
        if (size < 1 || size > MAX_PAGE_SIZE) {
            throw new IllegalArgumentException("size must be between 1 and " + MAX_PAGE_SIZE);
        }
        if (from != null && to != null && from.isAfter(to)) {
            throw new IllegalArgumentException("from must not be after to");
        }
    }
}
