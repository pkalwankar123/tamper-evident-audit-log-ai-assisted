package com.example.audit.security;

import com.example.audit.config.AuditProperties;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

/**
 * Derives the trusted {@link AuthenticatedActor} from the authenticated principal.
 *
 * <p>This class replaces the previous "validate the actorId the caller sent" model.
 * Nothing here reads the request body or query parameters: the actor and tenant are
 * produced from the token or from the configured principal binding, and the caller has
 * no way to influence them. Requests that used to carry {@code actorId} simply no
 * longer have that field.
 *
 * <p>Resolution fails closed. A principal with no tenant, or no actor, is rejected with
 * {@link AccessDeniedException} rather than being defaulted to anything.
 */
@Component
public class ActorResolver {
    public static final String ROLE_ADMIN = "ROLE_AUDIT_ADMIN";
    public static final String ROLE_WRITER = "ROLE_AUDIT_WRITER";
    public static final String ROLE_READER = "ROLE_AUDIT_READER";

    private final AuditProperties properties;

    public ActorResolver(AuditProperties properties) {
        this.properties = properties;
    }

    public AuthenticatedActor resolve(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AccessDeniedException("Unauthenticated request cannot be attributed to an actor");
        }
        boolean admin = hasRole(authentication, ROLE_ADMIN);
        if (authentication instanceof JwtAuthenticationToken jwtAuthentication) {
            return fromJwt(jwtAuthentication.getToken(), admin);
        }
        return fromBinding(authentication.getName(), admin);
    }

    private AuthenticatedActor fromJwt(Jwt jwt, boolean admin) {
        AuditProperties.Identity identity = properties.getIdentity();
        String actorId = stringClaim(jwt, identity.getActorClaim());
        String tenantId = stringClaim(jwt, identity.getTenantClaim());
        if (actorId == null || actorId.isBlank()) {
            throw new AccessDeniedException(
                    "Token is missing the required actor claim '" + identity.getActorClaim() + "'");
        }
        if (tenantId == null || tenantId.isBlank()) {
            throw new AccessDeniedException(
                    "Token is missing the required tenant claim '" + identity.getTenantClaim() + "'");
        }
        String username = jwt.getSubject() == null ? actorId : jwt.getSubject();
        return new AuthenticatedActor(username, actorId, tenantId, admin);
    }

    private AuthenticatedActor fromBinding(String username, boolean admin) {
        AuditProperties.PrincipalBinding binding = properties.getIdentity().getPrincipals().get(username);
        if (binding == null || binding.getActorId().isBlank() || binding.getTenantId().isBlank()) {
            throw new AccessDeniedException(
                    "No actor/tenant identity binding is configured for principal '" + username + "'");
        }
        return new AuthenticatedActor(username, binding.getActorId(), binding.getTenantId(), admin);
    }

    private static String stringClaim(Jwt jwt, String claim) {
        Object value = jwt.getClaim(claim);
        return value == null ? null : value.toString();
    }

    private static boolean hasRole(Authentication authentication, String role) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(role::equals);
    }
}
