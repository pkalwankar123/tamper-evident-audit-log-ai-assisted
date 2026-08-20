package com.example.audit;

import com.example.audit.api.ApiModels;
import com.example.audit.repository.AuditRecordRepository;
import com.example.audit.repository.ChainCheckpointRepository;
import com.example.audit.repository.ChainHeadRepository;
import com.example.audit.repository.IdempotencyRecordRepository;
import com.example.audit.repository.RedactionEntryRepository;
import com.example.audit.security.AuthenticatedActor;
import com.example.audit.service.AuditService;
import com.example.audit.service.CheckpointService;
import com.example.audit.service.ExportService;
import com.example.audit.service.RetentionService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.access.AccessDeniedException;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.NoSuchElementException;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Authorization proven at the service layer, with no HTTP involved.
 *
 * <p>This suite exists because controller-level tests only prove that <em>this</em>
 * controller enforces the rules. Driving the services directly proves the guarantee
 * holds for any caller - a future controller, a scheduled job, a message consumer - and
 * that it cannot be bypassed by reaching past the web tier.
 *
 * <p>The scenarios are the ones the gate names explicitly: actor-a must not reach
 * actor-b's data, and tenant-a must not reach tenant-b's data, on create, query, verify,
 * export, redact and archive.
 */
@SpringBootTest
class ServiceLayerAuthorizationTest {

    @Autowired AuditService auditService;
    @Autowired ExportService exportService;
    @Autowired RetentionService retentionService;
    @Autowired CheckpointService checkpointService;
    @Autowired ObjectMapper mapper;
    @Autowired AuditRecordRepository recordRepository;
    @Autowired RedactionEntryRepository redactionRepository;
    @Autowired ChainHeadRepository chainHeadRepository;
    @Autowired ChainCheckpointRepository checkpointRepository;
    @Autowired IdempotencyRecordRepository idempotencyRepository;

    private static final AuthenticatedActor ACTOR_A = new AuthenticatedActor("a", "actor-a", "tenant-a", false);
    private static final AuthenticatedActor ACTOR_B = new AuthenticatedActor("b", "actor-b", "tenant-a", false);
    private static final AuthenticatedActor ADMIN_A = new AuthenticatedActor("adm-a", "admin-a", "tenant-a", true);
    private static final AuthenticatedActor ADMIN_B = new AuthenticatedActor("adm-b", "admin-b", "tenant-b", true);
    private static final AuthenticatedActor ACTOR_TENANT_B =
            new AuthenticatedActor("tb", "actor-tb", "tenant-b", false);

    @BeforeEach
    void reset() {
        redactionRepository.deleteAll();
        checkpointRepository.deleteAll();
        idempotencyRepository.deleteAll();
        recordRepository.deleteAll();
        chainHeadRepository.deleteAll();
    }

    private ApiModels.CreateAuditEventRequest request(String eventType, String resourceId) throws Exception {
        return new ApiModels.CreateAuditEventRequest(eventType, "ACCOUNT", resourceId,
                mapper.readTree("{\"k\":\"v\"}"), null);
    }

    private ApiModels.AuditEventResponse append(AuthenticatedActor actor, String resourceId) throws Exception {
        return auditService.append(actor, request("EVT", resourceId), null).event();
    }

    // ------------------------------------------------------------------
    // Create - identity is derived, never supplied
    // ------------------------------------------------------------------

    @Test
    @DisplayName("append stamps the actor and tenant from the principal, not from the request")
    void appendDerivesIdentityFromPrincipal() throws Exception {
        ApiModels.AuditEventResponse created = append(ACTOR_A, "r-1");

        assertThat(created.actorId()).isEqualTo("actor-a");
        assertThat(created.tenantId()).isEqualTo("tenant-a");
        // And it is what was actually persisted, not just what was echoed back.
        assertThat(recordRepository.findById(created.id()).orElseThrow().getActorId()).isEqualTo("actor-a");
        assertThat(recordRepository.findById(created.id()).orElseThrow().getTenantId()).isEqualTo("tenant-a");
    }

    @Test
    @DisplayName("each tenant gets an independent chain starting at index 1")
    void tenantsHaveIndependentChains() throws Exception {
        ApiModels.AuditEventResponse first = append(ACTOR_A, "r-1");
        ApiModels.AuditEventResponse other = append(ACTOR_TENANT_B, "r-1");

        assertThat(first.chainIndex()).isEqualTo(1L);
        assertThat(other.chainIndex()).isEqualTo(1L);
        assertThat(other.previousHash()).isEqualTo(AuditService.GENESIS_HASH);
        // Independent chains means tenant-b's record must not link into tenant-a's.
        assertThat(other.recordHash()).isNotEqualTo(first.recordHash());
    }

    // ------------------------------------------------------------------
    // Query - actor ownership within a tenant
    // ------------------------------------------------------------------

    @Test
    @DisplayName("actor-a cannot query actor-b's records by explicit filter")
    void actorCannotQueryAnotherActorByFilter() throws Exception {
        append(ACTOR_B, "r-b");

        assertThatThrownBy(() -> auditService.query(ACTOR_A, "actor-b", null, null, null, null, null, false,
                PageRequest.of(0, 50)))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("actor-b");
    }

    @Test
    @DisplayName("an unfiltered query is pinned to the caller's own actor, not widened")
    void unfilteredQueryIsPinnedToOwnActor() throws Exception {
        append(ACTOR_A, "r-a");
        append(ACTOR_B, "r-b");

        Page<ApiModels.AuditEventResponse> page =
                auditService.query(ACTOR_A, null, null, null, null, null, null, false, PageRequest.of(0, 50));

        assertThat(page.getTotalElements()).isEqualTo(1);
        assertThat(page.getContent().get(0).actorId()).isEqualTo("actor-a");
        assertThat(page.getContent()).noneMatch(event -> event.actorId().equals("actor-b"));
    }

    @Test
    @DisplayName("an admin sees every actor in its own tenant and none from another")
    void adminSeesOwnTenantOnly() throws Exception {
        append(ACTOR_A, "r-a");
        append(ACTOR_B, "r-b");
        append(ACTOR_TENANT_B, "r-tb");

        Page<ApiModels.AuditEventResponse> page =
                auditService.query(ADMIN_A, null, null, null, null, null, null, false, PageRequest.of(0, 50));

        assertThat(page.getTotalElements()).isEqualTo(2);
        assertThat(page.getContent()).allMatch(event -> event.tenantId().equals("tenant-a"));
    }

    // ------------------------------------------------------------------
    // Tenant isolation - the axis that binds administrators too
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a tenant-b admin cannot query tenant-a data even by naming its actor")
    void tenantBAdminCannotQueryTenantA() throws Exception {
        append(ACTOR_A, "r-a");

        Page<ApiModels.AuditEventResponse> page =
                auditService.query(ADMIN_B, "actor-a", null, null, null, null, null, false, PageRequest.of(0, 50));

        // Admin may name any actor, but the tenant predicate is not negotiable, so the
        // result is empty rather than another tenant's data.
        assertThat(page.getTotalElements()).isZero();
    }

    @Test
    @DisplayName("fetching a record by id across a tenant boundary is denied")
    void crossTenantFetchByIdIsDenied() throws Exception {
        UUID id = append(ACTOR_A, "r-a").id();

        assertThatThrownBy(() -> auditService.findById(ADMIN_B, id))
                .isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> auditService.findById(ACTOR_TENANT_B, id))
                .isInstanceOf(AccessDeniedException.class);
        // The owning tenant's admin can, so the denial is about tenancy and not a broken lookup.
        assertThatCode(() -> auditService.findById(ADMIN_A, id)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("actor-a cannot fetch actor-b's record by id")
    void crossActorFetchByIdIsDenied() throws Exception {
        UUID id = append(ACTOR_B, "r-b").id();

        assertThatThrownBy(() -> auditService.findById(ACTOR_A, id))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    @DisplayName("verify only covers the caller's own tenant")
    void verifyIsTenantScoped() throws Exception {
        append(ACTOR_A, "r-a");
        append(ACTOR_B, "r-b");
        append(ACTOR_TENANT_B, "r-tb");

        assertThat(auditService.verify(ADMIN_A).checkedRecords()).isEqualTo(2);
        assertThat(auditService.verify(ADMIN_B).checkedRecords()).isEqualTo(1);
        assertThat(auditService.verify(ADMIN_A).intact()).isTrue();
    }

    // ------------------------------------------------------------------
    // Redaction, export, archive, checkpoints - privileged operations
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a non-admin cannot redact, even its own record")
    void nonAdminCannotRedact() throws Exception {
        UUID id = append(ACTOR_A, "r-a").id();

        assertThatThrownBy(() -> auditService.redact(ACTOR_A, id, new ApiModels.RedactionRequest("/k", "why")))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("ROLE_AUDIT_ADMIN");
    }

    @Test
    @DisplayName("a tenant-b admin cannot redact a tenant-a record")
    void crossTenantRedactIsDenied() throws Exception {
        UUID id = append(ACTOR_A, "r-a").id();

        assertThatThrownBy(() -> auditService.redact(ADMIN_B, id, new ApiModels.RedactionRequest("/k", "why")))
                .isInstanceOf(AccessDeniedException.class);
        // The record is untouched by the rejected attempt.
        assertThat(recordRepository.findById(id).orElseThrow().getPayloadJson()).contains("\"v\"");
        assertThat(redactionRepository.findByRecordIdOrderBySequenceNumberAsc(id)).isEmpty();
    }

    @Test
    @DisplayName("the redacting actor recorded in the ledger comes from the principal")
    void redactionActorComesFromPrincipal() throws Exception {
        UUID id = append(ACTOR_A, "r-a").id();

        auditService.redact(ADMIN_A, id, new ApiModels.RedactionRequest("/k", "privacy request"));

        assertThat(redactionRepository.findByRecordIdOrderBySequenceNumberAsc(id))
                .singleElement()
                .satisfies(entry -> {
                    assertThat(entry.getActorId()).isEqualTo("admin-a");
                    assertThat(entry.getTenantId()).isEqualTo("tenant-a");
                });
        assertThat(auditService.verify(ADMIN_A).intact()).isTrue();
    }

    @Test
    @DisplayName("a non-admin cannot export")
    void nonAdminCannotExport() throws Exception {
        append(ACTOR_A, "r-a");

        assertThatThrownBy(() -> exportService.export(ACTOR_A, "actor-a", null))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    @DisplayName("export cannot reach across tenants")
    void exportIsTenantScoped() throws Exception {
        append(ACTOR_A, "r-a");

        // tenant-b's admin asking for tenant-a's actor finds nothing to export.
        assertThatThrownBy(() -> exportService.export(ADMIN_B, "actor-a", null))
                .isInstanceOf(NoSuchElementException.class);

        ApiModels.ExportManifest own = exportService.export(ADMIN_A, "actor-a", null);
        assertThat(own.tenantId()).isEqualTo("tenant-a");
        assertThat(own.records()).allMatch(record -> record.event().tenantId().equals("tenant-a"));
    }

    @Test
    @DisplayName("a non-admin cannot archive, and archiving never crosses a tenant")
    void archiveIsAdminOnlyAndTenantScoped() throws Exception {
        append(ACTOR_A, "r-a");
        append(ACTOR_TENANT_B, "r-tb");
        Instant future = Instant.now().plus(1, ChronoUnit.DAYS);

        assertThatThrownBy(() -> auditService.archiveOlderThan(ACTOR_A, future))
                .isInstanceOf(AccessDeniedException.class);

        assertThat(auditService.archiveOlderThan(ADMIN_A, future)).isEqualTo(1);
        // tenant-b's single record is untouched by tenant-a's sweep.
        assertThat(recordRepository.findByTenantIdOrderByChainIndexAsc("tenant-b"))
                .singleElement()
                .satisfies(record -> assertThat(record.isArchived()).isFalse());
    }

    @Test
    @DisplayName("retention run is refused for a non-admin")
    void retentionRunIsAdminOnly() {
        assertThatThrownBy(() -> retentionService.applyRetentionPolicy(ACTOR_A))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    @DisplayName("checkpoint creation and listing are admin-only")
    void checkpointsAreAdminOnly() throws Exception {
        append(ACTOR_A, "r-a");

        assertThatThrownBy(() -> checkpointService.createCheckpoint(ACTOR_A))
                .isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> checkpointService.listCheckpoints(ACTOR_A))
                .isInstanceOf(AccessDeniedException.class);
        assertThat(checkpointService.createCheckpoint(ADMIN_A).tenantId()).isEqualTo("tenant-a");
    }

    @Test
    @DisplayName("a tenant's checkpoints are invisible to another tenant")
    void checkpointsAreTenantScoped() throws Exception {
        append(ACTOR_A, "r-a");
        checkpointService.createCheckpoint(ADMIN_A);

        assertThat(checkpointService.listCheckpoints(ADMIN_A)).hasSize(1);
        assertThat(checkpointService.listCheckpoints(ADMIN_B)).isEmpty();
    }
}
