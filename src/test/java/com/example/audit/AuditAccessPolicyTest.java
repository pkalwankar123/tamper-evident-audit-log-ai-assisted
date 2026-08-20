package com.example.audit;

import com.example.audit.config.AuditProperties;
import com.example.audit.domain.AuditRecord;
import com.example.audit.security.ActorResolver;
import com.example.audit.security.AuditAccessPolicy;
import com.example.audit.security.AuthenticatedActor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The authorization rules and identity derivation as plain units - no Spring context, no
 * database.
 *
 * <p>The integration suites prove the rules hold in the running application; this proves
 * each rule in isolation, so a failure points at the rule rather than at whichever
 * scenario happened to exercise it.
 */
class AuditAccessPolicyTest {

    private final AuditAccessPolicy policy = new AuditAccessPolicy();

    private static final AuthenticatedActor USER_A = new AuthenticatedActor("ua", "actor-a", "tenant-a", false);
    private static final AuthenticatedActor ADMIN_A = new AuthenticatedActor("aa", "admin-a", "tenant-a", true);
    private static final AuthenticatedActor ADMIN_B = new AuthenticatedActor("ab", "admin-b", "tenant-b", true);

    private static AuditRecord recordFor(String tenantId, String actorId) {
        return new AuditRecord(tenantId, 1L, "EVT", actorId, "ACCOUNT", "r-1", Instant.now(), Instant.now(),
                "{}", "commitment", "previous", "hash");
    }

    // ---------------------------------------------------------------
    // Role gate
    // ---------------------------------------------------------------

    @Test
    void adminOnlyOperationsRejectNonAdmins() {
        assertThatThrownBy(() -> policy.requireAdmin(USER_A, "export"))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("ROLE_AUDIT_ADMIN");
        assertThatCode(() -> policy.requireAdmin(ADMIN_A, "export")).doesNotThrowAnyException();
    }

    // ---------------------------------------------------------------
    // Query scoping
    // ---------------------------------------------------------------

    @Test
    @DisplayName("a non-admin querying without a filter is pinned to its own actor")
    void unfilteredQueryIsPinned() {
        assertThat(policy.resolveQueryActorId(USER_A, null)).isEqualTo("actor-a");
    }

    @Test
    @DisplayName("a non-admin naming its own actor is allowed")
    void ownActorFilterIsAllowed() {
        assertThat(policy.resolveQueryActorId(USER_A, "actor-a")).isEqualTo("actor-a");
    }

    @Test
    @DisplayName("a non-admin naming another actor is denied, not silently rewritten")
    void otherActorFilterIsDenied() {
        assertThatThrownBy(() -> policy.resolveQueryActorId(USER_A, "actor-b"))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    @DisplayName("an admin may name any actor, or none")
    void adminMayQueryAnyActor() {
        assertThat(policy.resolveQueryActorId(ADMIN_A, "actor-b")).isEqualTo("actor-b");
        assertThat(policy.resolveQueryActorId(ADMIN_A, null)).isNull();
    }

    // ---------------------------------------------------------------
    // Tenant and record access
    // ---------------------------------------------------------------

    @Test
    @DisplayName("tenant isolation binds administrators too")
    void tenantIsolationAppliesToAdmins() {
        assertThatThrownBy(() -> policy.requireTenant(ADMIN_B, "tenant-a"))
                .isInstanceOf(AccessDeniedException.class);
        assertThatCode(() -> policy.requireTenant(ADMIN_A, "tenant-a")).doesNotThrowAnyException();
    }

    @Test
    void recordAccessChecksTenantThenOwnership() {
        assertThatThrownBy(() -> policy.requireRecordAccess(ADMIN_B, recordFor("tenant-a", "actor-a")))
                .isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> policy.requireRecordAccess(USER_A, recordFor("tenant-a", "actor-b")))
                .isInstanceOf(AccessDeniedException.class);
        assertThatCode(() -> policy.requireRecordAccess(USER_A, recordFor("tenant-a", "actor-a")))
                .doesNotThrowAnyException();
        // An admin reaches any actor inside its own tenant.
        assertThatCode(() -> policy.requireRecordAccess(ADMIN_A, recordFor("tenant-a", "actor-b")))
                .doesNotThrowAnyException();
    }

    // ---------------------------------------------------------------
    // Identity derivation
    // ---------------------------------------------------------------

    @Test
    @DisplayName("a principal with no configured binding is denied rather than defaulted")
    void unboundPrincipalIsDenied() {
        ActorResolver resolver = new ActorResolver(new AuditProperties());

        assertThatThrownBy(() -> resolver.resolve(
                new UsernamePasswordAuthenticationToken("stranger", "n/a", List.of())))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("No actor/tenant identity binding");
    }

    @Test
    @DisplayName("a binding missing its tenant is treated as no binding at all")
    void partialBindingIsDenied() {
        AuditProperties properties = new AuditProperties();
        AuditProperties.PrincipalBinding binding = new AuditProperties.PrincipalBinding();
        binding.setActorId("actor-a");
        properties.getIdentity().getPrincipals().put("halfway", binding);

        assertThatThrownBy(() -> new ActorResolver(properties).resolve(
                new UsernamePasswordAuthenticationToken("halfway", "n/a", List.of())))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    @DisplayName("a configured binding yields the actor, tenant and admin flag")
    void configuredBindingResolves() {
        AuditProperties properties = new AuditProperties();
        AuditProperties.PrincipalBinding binding = new AuditProperties.PrincipalBinding();
        binding.setActorId("actor-a");
        binding.setTenantId("tenant-a");
        properties.getIdentity().getPrincipals().put("bound", binding);

        AuthenticatedActor actor = new ActorResolver(properties).resolve(
                new UsernamePasswordAuthenticationToken("bound", "n/a",
                        List.of(new SimpleGrantedAuthority("ROLE_AUDIT_ADMIN"))));

        assertThat(actor.actorId()).isEqualTo("actor-a");
        assertThat(actor.tenantId()).isEqualTo("tenant-a");
        assertThat(actor.admin()).isTrue();
    }

    @Test
    void nullAuthenticationIsDenied() {
        assertThatThrownBy(() -> new ActorResolver(new AuditProperties()).resolve(null))
                .isInstanceOf(AccessDeniedException.class);
    }
}
