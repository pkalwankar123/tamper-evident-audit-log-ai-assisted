package com.example.audit.security;

/**
 * The server-derived identity used for every authorization decision and for every
 * value persisted onto an audit record.
 *
 * <p>Instances are only ever produced by {@link ActorResolver} from the authenticated
 * principal (JWT claims, or the local Basic-auth binding table). No field here can be
 * influenced by the request body or query string - that is the whole point of the
 * type: if a value is in {@code AuthenticatedActor}, it is trustworthy.
 *
 * @param username  the authenticated principal name (token subject, or Basic username)
 * @param actorId   the business actor this principal acts as
 * @param tenantId  the tenant this principal belongs to; every read and write is
 *                  confined to it, administrators included
 * @param admin     whether the principal holds {@code ROLE_AUDIT_ADMIN} - which grants
 *                  cross-actor access <em>within the tenant only</em>, never across
 *                  tenants
 */
public record AuthenticatedActor(String username, String actorId, String tenantId, boolean admin) {
}
