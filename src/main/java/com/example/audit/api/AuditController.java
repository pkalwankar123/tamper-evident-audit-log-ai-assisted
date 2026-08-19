package com.example.audit.api;

import com.example.audit.service.AuditService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

@RestController
@RequestMapping("/audit")
@Tag(name = "Audit Log", description = "Append, query, and verify tamper-evident audit events")
public class AuditController {
    private final AuditService auditService;

    public AuditController(AuditService auditService) {
        this.auditService = auditService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Append audit event", description = "Creates an append-only record linked into the SHA-256 hash chain.")
    public ApiModels.AuditEventResponse append(@Valid @RequestBody ApiModels.CreateAuditEventRequest request) {
        return auditService.append(request);
    }

    @GetMapping
    @Operation(summary = "Query audit events", description = "Filter by actor/resource/event/time. Archived excluded unless includeArchived=true.")
    public Page<ApiModels.AuditEventResponse> query(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceType,
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @RequestParam(defaultValue = "false") boolean includeArchived,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        int safeSize = Math.min(Math.max(size, 1), 500);
        return auditService.query(actorId, resourceType, resourceId, eventType, from, to, includeArchived,
                PageRequest.of(Math.max(page, 0), safeSize, Sort.by("chainIndex").ascending()));
    }

    @GetMapping("/verify")
    @Operation(summary = "Verify hash chain", description = "Recomputes the full chain (including archived). Returns intact=false on tamper.")
    public ApiModels.VerificationResponse verify() {
        return auditService.verify();
    }
}
