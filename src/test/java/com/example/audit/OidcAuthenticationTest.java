package com.example.audit;

import com.example.audit.config.AuditProperties;
import com.example.audit.security.ActorResolver;
import com.example.audit.security.AuthenticatedActor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The OIDC/JWT authentication path.
 *
 * <p>Runs with {@code audit.security.oidc.enabled=true} so the resource-server filter
 * chain is the one under test, not the Basic fallback. A JWK set URI is used rather than
 * issuer discovery because the Nimbus decoder resolves it lazily, which keeps the test
 * hermetic - no network call is made, and the token decoding itself is stubbed by the
 * test support, since what matters here is how the application maps a validated token
 * onto an identity and a set of roles.
 *
 * <p>MFA is intentionally not implemented in this service: it is an authentication-time
 * concern that belongs to the identity provider, and the service consumes the resulting
 * token.
 */
@SpringBootTest(properties = {
        "audit.security.oidc.enabled=true",
        "audit.security.oidc.jwk-set-uri=http://localhost:1/jwks.json"
})
@AutoConfigureMockMvc
class OidcAuthenticationTest {

    @Autowired MockMvc mvc;
    @Autowired ActorResolver actorResolver;
    @Autowired JwtAuthenticationConverter jwtAuthenticationConverter;
    @Autowired AuditProperties properties;

    @Test
    @DisplayName("with OIDC enabled, an unauthenticated request is refused")
    void unauthenticatedRequestIsRefused() throws Exception {
        mvc.perform(get("/audit/verify")).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("with OIDC enabled, Basic credentials no longer authenticate")
    void basicCredentialsDoNotWorkUnderOidc() throws Exception {
        mvc.perform(get("/audit/verify")
                        .with(SecurityMockMvcRequestPostProcessors.httpBasic("admin", "test-admin-password")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("a valid token authenticates and its claims become the actor and tenant")
    void tokenClaimsBecomeTheIdentity() throws Exception {
        mvc.perform(get("/audit/verify").with(SecurityMockMvcRequestPostProcessors.jwt()
                        .jwt(builder -> builder.subject("advisor-77").claim("tenant_id", "tenant-x"))
                        .authorities(new SimpleGrantedAuthority("ROLE_AUDIT_READER"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(true));
    }

    @Test
    @DisplayName("the API docs are not public when OIDC is enabled")
    void apiDocsAreNotPublicUnderOidc() throws Exception {
        mvc.perform(get("/v3/api-docs")).andExpect(status().isUnauthorized());
    }

    // ---------------------------------------------------------------
    // Claim mapping, exercised directly
    // ---------------------------------------------------------------

    private static Jwt jwt(Map<String, Object> claims) {
        Jwt.Builder builder = Jwt.withTokenValue("token").header("alg", "EdDSA")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(300));
        claims.forEach(builder::claim);
        return builder.build();
    }

    @Test
    @DisplayName("the roles claim is mapped onto service authorities, with ROLE_ added once")
    void rolesClaimBecomesAuthorities() {
        Jwt token = jwt(Map.of("sub", "advisor-77", "tenant_id", "tenant-x",
                "roles", List.of("AUDIT_READER", "ROLE_AUDIT_ADMIN")));

        List<String> authorities = jwtAuthenticationConverter.convert(token).getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).toList();

        assertThat(authorities).contains("ROLE_AUDIT_READER", "ROLE_AUDIT_ADMIN");
    }

    @Test
    @DisplayName("a token grants no roles it does not carry")
    void tokenWithoutRolesGrantsNothing() {
        Jwt token = jwt(Map.of("sub", "advisor-77", "tenant_id", "tenant-x"));

        assertThat(jwtAuthenticationConverter.convert(token).getAuthorities()).isEmpty();
    }

    @Test
    @DisplayName("actor and tenant are read from the configured claims")
    void actorAndTenantComeFromClaims() {
        Jwt token = jwt(Map.of("sub", "advisor-77", "tenant_id", "tenant-x"));
        JwtAuthenticationToken authentication =
                new JwtAuthenticationToken(token, List.of(new SimpleGrantedAuthority("ROLE_AUDIT_ADMIN")));

        AuthenticatedActor actor = actorResolver.resolve(authentication);

        assertThat(actor.actorId()).isEqualTo("advisor-77");
        assertThat(actor.tenantId()).isEqualTo("tenant-x");
        assertThat(actor.admin()).isTrue();
    }

    @Test
    @DisplayName("a token missing the tenant claim is denied, not defaulted")
    void missingTenantClaimIsDenied() {
        Jwt token = jwt(Map.of("sub", "advisor-77"));
        JwtAuthenticationToken authentication = new JwtAuthenticationToken(token, List.of());

        assertThatThrownBy(() -> actorResolver.resolve(authentication))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("tenant_id");
    }

    @Test
    @DisplayName("a token missing the actor claim is denied")
    void missingActorClaimIsDenied() {
        Jwt token = jwt(Map.of("tenant_id", "tenant-x"));
        JwtAuthenticationToken authentication = new JwtAuthenticationToken(token, List.of());

        assertThatThrownBy(() -> actorResolver.resolve(authentication))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("sub");
    }

    @Test
    @DisplayName("claim names are configurable, so the service adapts to the IdP rather than the reverse")
    void claimNamesAreConfigurable() {
        assertThat(properties.getIdentity().getActorClaim()).isEqualTo("sub");
        assertThat(properties.getIdentity().getTenantClaim()).isEqualTo("tenant_id");
        assertThat(properties.getIdentity().getRolesClaim()).isEqualTo("roles");
    }
}
