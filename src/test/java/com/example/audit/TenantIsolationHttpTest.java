package com.example.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tenant isolation over the real HTTP stack, with tenancy arriving the way it does in
 * production - as a token claim.
 *
 * <p>Using JWT principals here is not a shortcut around the security config; it is the
 * production mechanism. It also gives the suite a second tenant without inventing a
 * second set of local Basic users, which would only have tested the test fixture.
 */
class TenantIsolationHttpTest extends AbstractAuditTest {
    private static final String WRITER = "ROLE_AUDIT_WRITER";
    private static final String READER = "ROLE_AUDIT_READER";
    private static final String ADMIN = "ROLE_AUDIT_ADMIN";

    @Test
    @DisplayName("a tenant-b token cannot see tenant-a records")
    void tenantBCannotReadTenantA() throws Exception {
        mvc.perform(post("/audit").with(asWriter()).contentType(MediaType.APPLICATION_JSON)
                        .content(eventBody("TENANT_A_EVENT", "r-1")))
                .andExpect(status().isCreated());

        mvc.perform(get("/audit").with(asToken("actor-b", TENANT_B, READER, ADMIN)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(0));
    }

    @Test
    @DisplayName("a tenant-b admin cannot fetch a tenant-a record by id")
    void tenantBAdminCannotFetchTenantARecordById() throws Exception {
        String created = mvc.perform(post("/audit").with(asWriter()).contentType(MediaType.APPLICATION_JSON)
                        .content(eventBody("X", "r-1")))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        UUID id = UUID.fromString(mapper.readTree(created).get("id").asText());

        mvc.perform(get("/audit/{id}", id).with(asToken("actor-b", TENANT_B, READER, ADMIN)))
                .andExpect(status().isForbidden());
        mvc.perform(get("/audit/{id}", id).with(asAdmin()))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("a tenant-b admin cannot redact a tenant-a record")
    void tenantBAdminCannotRedactTenantARecord() throws Exception {
        String created = mvc.perform(post("/audit").with(asAdmin()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"eventType\":\"X\",\"resourceType\":\"ACCOUNT\",\"resourceId\":\"r-1\","
                                + "\"payload\":{\"secret\":\"value\"}}"))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        UUID id = UUID.fromString(mapper.readTree(created).get("id").asText());

        mvc.perform(post("/audit/{id}/redact", id).with(asToken("actor-b", TENANT_B, ADMIN))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fieldPath\":\"/secret\",\"reason\":\"nosy\"}"))
                .andExpect(status().isForbidden());

        // The payload is untouched, and nothing was written to the redaction ledger.
        assertThat(recordRepository.findById(id).orElseThrow().getPayloadJson()).contains("value");
        assertThat(redactionRepository.findByRecordIdOrderBySequenceNumberAsc(id)).isEmpty();
    }

    @Test
    @DisplayName("a tenant-b admin cannot export tenant-a data")
    void tenantBAdminCannotExportTenantA() throws Exception {
        mvc.perform(post("/audit").with(asWriter()).contentType(MediaType.APPLICATION_JSON)
                        .content(eventBody("X", "r-1"))).andExpect(status().isCreated());

        mvc.perform(get("/audit/export").with(asToken("actor-b", TENANT_B, ADMIN))
                        .param("actorId", ADVISOR_17))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("archiving in one tenant leaves another tenant untouched")
    void archiveDoesNotCrossTenants() throws Exception {
        mvc.perform(post("/audit").with(asWriter()).contentType(MediaType.APPLICATION_JSON)
                        .content(eventBody("A", "r-1"))).andExpect(status().isCreated());
        mvc.perform(post("/audit").with(asToken("actor-b", TENANT_B, WRITER))
                        .contentType(MediaType.APPLICATION_JSON).content(eventBody("B", "r-2")))
                .andExpect(status().isCreated());

        mvc.perform(post("/audit/archive").with(asAdmin()).param("olderThanDays", "0"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.archivedCount").value(1))
                .andExpect(jsonPath("$.tenantId").value(TENANT_A));

        assertThat(recordRepository.findByTenantIdOrderByChainIndexAsc(TENANT_B))
                .singleElement()
                .satisfies(record -> assertThat(record.isArchived()).isFalse());
    }

    @Test
    @DisplayName("verification counts only the caller's own tenant")
    void verifyIsScopedToTheCallersTenant() throws Exception {
        mvc.perform(post("/audit").with(asWriter()).contentType(MediaType.APPLICATION_JSON)
                        .content(eventBody("A", "r-1"))).andExpect(status().isCreated());
        mvc.perform(post("/audit").with(asToken("actor-b", TENANT_B, WRITER))
                        .contentType(MediaType.APPLICATION_JSON).content(eventBody("B", "r-2")))
                .andExpect(status().isCreated());
        mvc.perform(post("/audit").with(asToken("actor-b", TENANT_B, WRITER))
                        .contentType(MediaType.APPLICATION_JSON).content(eventBody("B2", "r-3")))
                .andExpect(status().isCreated());

        mvc.perform(get("/audit/verify").with(asAdmin()))
                .andExpect(jsonPath("$.intact").value(true))
                .andExpect(jsonPath("$.checkedRecords").value(1));
        mvc.perform(get("/audit/verify").with(asToken("actor-b", TENANT_B, READER)))
                .andExpect(jsonPath("$.intact").value(true))
                .andExpect(jsonPath("$.checkedRecords").value(2));
    }

    @Test
    @DisplayName("a token with no tenant claim is denied rather than defaulted")
    void tokenWithoutTenantClaimIsDenied() throws Exception {
        mvc.perform(get("/audit/verify")
                        .with(org.springframework.security.test.web.servlet.request
                                .SecurityMockMvcRequestPostProcessors.jwt()
                                .jwt(builder -> builder.subject("no-tenant"))
                                .authorities(new org.springframework.security.core.authority
                                        .SimpleGrantedAuthority(READER))))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("an idempotency key is scoped to its tenant")
    void idempotencyKeysAreTenantScoped() throws Exception {
        mvc.perform(post("/audit").with(asWriter()).header("Idempotency-Key", "shared-key")
                        .contentType(MediaType.APPLICATION_JSON).content(eventBody("A", "r-1")))
                .andExpect(status().isCreated());

        // The same key in another tenant is a different key, so this is a real append.
        mvc.perform(post("/audit").with(asToken("actor-b", TENANT_B, WRITER)).header("Idempotency-Key", "shared-key")
                        .contentType(MediaType.APPLICATION_JSON).content(eventBody("A", "r-1")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.tenantId").value(TENANT_B));

        assertThat(recordRepository.count()).isEqualTo(2);
    }
}
