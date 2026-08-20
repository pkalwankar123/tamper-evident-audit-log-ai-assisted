package com.example.audit.service;

import com.example.audit.config.AuditProperties;
import com.example.audit.domain.ChainHead;
import com.example.audit.repository.ChainHeadRepository;
import com.example.audit.security.AuthenticatedActor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * The retention lifecycle.
 *
 * <p>Records pass through exactly two states: <b>active</b> until they are older than
 * {@code audit.retention.days}, then <b>archived</b>. Archiving is a soft state change -
 * the row, its payload, its hashes and its chain links all survive untouched, so an
 * archived record still verifies and still exports. Nothing in this service deletes an
 * audit record; hard deletion would break the chain by construction and is not offered.
 *
 * <p>Two entry points, with different authorization stories:
 * <ul>
 *   <li>the scheduled sweep, gated behind {@code audit.retention.enabled}, running as
 *       the system across every known tenant;</li>
 *   <li>an on-demand admin trigger, whose authentication and {@code ROLE_AUDIT_ADMIN}
 *       check are its authorization, scoped to the caller's own tenant.</li>
 * </ul>
 */
@Service
public class RetentionService {
    private static final Logger LOGGER = LoggerFactory.getLogger(RetentionService.class);

    private final AuditService auditService;
    private final ChainHeadRepository chainHeads;
    private final AuditProperties properties;

    public RetentionService(AuditService auditService, ChainHeadRepository chainHeads,
                            AuditProperties properties) {
        this.auditService = auditService;
        this.chainHeads = chainHeads;
        this.properties = properties;
    }

    @Scheduled(cron = "${audit.retention.cron:0 0 2 * * *}")
    public void scheduledRetentionSweep() {
        if (!properties.getRetention().isEnabled()) {
            return;
        }
        for (ChainHead head : chainHeads.findAll()) {
            int archived = archiveForTenant(systemActorFor(head.getTenantId()), retentionCutoff());
            if (archived > 0) {
                LOGGER.info("Retention sweep archived {} record(s) for tenant {}", archived, head.getTenantId());
            }
        }
    }

    /** On-demand sweep for the caller's own tenant. Authorization is checked downstream. */
    public int applyRetentionPolicy(AuthenticatedActor actor) {
        return archiveForTenant(actor, retentionCutoff());
    }

    /** On-demand archive with an explicit age, for operational use. */
    public int archiveOlderThanDays(AuthenticatedActor actor, int days) {
        if (days < 0) {
            throw new IllegalArgumentException("olderThanDays must be >= 0");
        }
        return archiveForTenant(actor, Instant.now().minus(days, ChronoUnit.DAYS));
    }

    private int archiveForTenant(AuthenticatedActor actor, Instant cutoff) {
        return auditService.archiveOlderThan(actor, cutoff);
    }

    private Instant retentionCutoff() {
        return Instant.now().minus(properties.getRetention().getDays(), ChronoUnit.DAYS);
    }

    /**
     * The identity the scheduler acts under. It is confined to one tenant per iteration
     * rather than being a global bypass, so the sweep goes through the same tenant-scoped
     * code path - and the same authorization check - as a human administrator would.
     */
    private static AuthenticatedActor systemActorFor(String tenantId) {
        return new AuthenticatedActor("system-retention", "system-retention", tenantId, true);
    }
}
