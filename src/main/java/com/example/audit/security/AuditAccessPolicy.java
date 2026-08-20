package com.example.audit.security;

import com.example.audit.domain.AuditRecord;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

/**
 * The single place where "may this actor touch this data" is decided.
 *
 * <p>Deliberately a service-layer collaborator rather than a web filter or controller
 * concern: the enforcement has to hold for any caller of {@code AuditService} /
 * {@code ExportService} / {@code RetentionService}, and it has to be directly testable
 * without going through HTTP. {@code AuditAccessPolicyTest} and
 * {@code ServiceLayerAuthorizationTest} exercise it at exactly that level.
 *
 * <p>Two independent axes:
 * <ul>
 *   <li><b>Tenant</b> - absolute. Nobody, administrators included, may read, verify,
 *       export, archive or redact data outside their own tenant.</li>
 *   <li><b>Actor</b> - within a tenant, an administrator may act across actors; every
 *       other principal is confined to its own {@code actorId}.</li>
 * </ul>
 */
@Component
public class AuditAccessPolicy {

    public void requireAdmin(AuthenticatedActor actor, String action) {
        if (!actor.admin()) {
            throw new AccessDeniedException("Principal '" + actor.username()
                    + "' requires ROLE_AUDIT_ADMIN to perform: " + action);
        }
    }

    /**
     * Resolves the {@code actorId} a query may actually filter on.
     *
     * <p>A non-admin is always pinned to its own actor. If it explicitly asked for a
     * different one it gets an honest 403 rather than a silently-rewritten filter that
     * would return a confusing empty page. An admin may ask for any actor, or for none
     * (meaning every actor in its own tenant).
     */
    public String resolveQueryActorId(AuthenticatedActor actor, String requestedActorId) {
        if (actor.admin()) {
            return requestedActorId;
        }
        if (requestedActorId != null && !requestedActorId.equals(actor.actorId())) {
            throw new AccessDeniedException("Principal '" + actor.username()
                    + "' is not authorized to read data for actorId '" + requestedActorId + "'");
        }
        return actor.actorId();
    }

    /** Tenant isolation for a single record. Applies to admins too. */
    public void requireTenant(AuthenticatedActor actor, String recordTenantId) {
        if (!actor.tenantId().equals(recordTenantId)) {
            throw new AccessDeniedException("Principal '" + actor.username() + "' (tenant '"
                    + actor.tenantId() + "') is not authorized to access data in tenant '"
                    + recordTenantId + "'");
        }
    }

    /** Tenant isolation plus actor ownership for a single record. */
    public void requireRecordAccess(AuthenticatedActor actor, AuditRecord record) {
        requireTenant(actor, record.getTenantId());
        if (!actor.admin() && !actor.actorId().equals(record.getActorId())) {
            throw new AccessDeniedException("Principal '" + actor.username()
                    + "' is not authorized to access records owned by actorId '"
                    + record.getActorId() + "'");
        }
    }
}
