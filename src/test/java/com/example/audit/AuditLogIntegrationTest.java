package com.example.audit;

import com.example.audit.domain.AuditRecord;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The end-to-end story over HTTP, plus the authentication and role boundaries.
 *
 * <p>Ownership and tenant isolation are proven at the service layer in
 * {@code ServiceLayerAuthorizationTest} and over HTTP in {@code TenantIsolationHttpTest};
 * what this class adds is that the wiring in between - filters, matchers, status codes,
 * response bodies - behaves as intended.
 */
class AuditLogIntegrationTest extends AbstractAuditTest {

    @Autowired JdbcTemplate jdbcTemplate;

    @Test
    @DisplayName("append, query, verify, redact, then detect a direct database edit")
    void appendQueryVerifyRedactAndDetectDirectTampering() throws Exception {
        String body = """
                {"eventType":"CLIENT_DATA_ACCESSED","resourceType":"ACCOUNT","resourceId":"acct-100",
                 "payload":{"accountNumber":"123456789","purpose":"support"}}
                """;
        String response = mvc.perform(post("/audit").with(asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.recordHash").isNotEmpty())
                .andExpect(jsonPath("$.chainIndex").value(1))
                // Identity is server-derived: the body never mentioned an actor or tenant.
                .andExpect(jsonPath("$.actorId").value("admin-a"))
                .andExpect(jsonPath("$.tenantId").value(TENANT_A))
                .andExpect(jsonPath("$.previousHash").value("0".repeat(64)))
                .andReturn().getResponse().getContentAsString();
        UUID id = UUID.fromString(mapper.readTree(response).get("id").asText());

        mvc.perform(get("/audit").with(asAdmin()).param("actorId", "admin-a"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].id").value(id.toString()));

        mvc.perform(get("/audit/verify").with(asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(true))
                .andExpect(jsonPath("$.checkedRecords").value(1));

        mvc.perform(post("/audit/{id}/redact", id).with(asAdmin()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fieldPath\":\"/accountNumber\",\"reason\":\"privacy request\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.replacement").value("[REDACTED]"))
                .andExpect(jsonPath("$.redactionEntryHash").isNotEmpty());

        // A legitimate redaction keeps the chain verifiable and actually removes the value.
        mvc.perform(get("/audit/verify").with(asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(true));
        mvc.perform(get("/audit/{id}", id).with(asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.payload.accountNumber").value("[REDACTED]"))
                .andExpect(jsonPath("$.payload.purpose").value("support"));

        // Now an unauthorized edit straight into the database, bypassing the API.
        AuditRecord record = recordRepository.findById(id).orElseThrow();
        JsonNode altered = mapper.readTree(record.getPayloadJson());
        ((ObjectNode) altered).put("purpose", "tampered");
        record.setPayloadJson(mapper.writeValueAsString(altered));
        recordRepository.saveAndFlush(record);

        mvc.perform(get("/audit/verify").with(asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(false))
                .andExpect(jsonPath("$.violationType").value("PAYLOAD_OR_REDACTION_LEDGER_MISMATCH"))
                .andExpect(jsonPath("$.firstInconsistentRecordId").value(id.toString()));
    }

    @Test
    @DisplayName("reordering the chain is detected")
    void reorderingIsDetected() throws Exception {
        appendAsAdmin("A", "r-1");
        appendAsAdmin("B", "r-2");

        // The link columns are mapped updatable=false, so JPA will not write them - which
        // is the point. A real attacker edits the row directly, so this test does too.
        var all = recordRepository.findByTenantIdOrderByChainIndexAsc(TENANT_A);
        jdbcTemplate.update("update audit_records set previous_hash = ? where id = ?",
                "0".repeat(64), all.get(1).getId().toString());

        mvc.perform(get("/audit/verify").with(asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(false))
                .andExpect(jsonPath("$.violationType").value("PREVIOUS_HASH_MISMATCH"));
    }

    @Test
    @DisplayName("deleting a record from the middle of the chain is detected as a gap")
    void deletionIsDetected() throws Exception {
        appendAsAdmin("A", "r-1");
        appendAsAdmin("B", "r-2");
        appendAsAdmin("C", "r-3");

        var all = recordRepository.findByTenantIdOrderByChainIndexAsc(TENANT_A);
        recordRepository.delete(all.get(1));
        recordRepository.flush();

        mvc.perform(get("/audit/verify").with(asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(false))
                .andExpect(jsonPath("$.violationType").value("CHAIN_INDEX_GAP"));
    }

    // ---------------------------------------------------------------
    // Authentication - no credentials
    // ---------------------------------------------------------------

    @Test
    void appendWithoutCredentialsIsRejected() throws Exception {
        mvc.perform(post("/audit").contentType(MediaType.APPLICATION_JSON).content(eventBody("X", "1")))
                .andExpect(status().isUnauthorized());
        assertThat(recordRepository.count()).isZero();
    }

    @Test
    void queryWithoutCredentialsIsRejected() throws Exception {
        mvc.perform(get("/audit")).andExpect(status().isUnauthorized());
    }

    @Test
    void verifyWithoutCredentialsIsRejected() throws Exception {
        mvc.perform(get("/audit/verify")).andExpect(status().isUnauthorized());
    }

    @Test
    void exportWithoutCredentialsIsRejected() throws Exception {
        mvc.perform(get("/audit/export").param("actorId", ADVISOR_17)).andExpect(status().isUnauthorized());
    }

    @Test
    void checkpointCreationWithoutCredentialsIsRejected() throws Exception {
        mvc.perform(post("/audit/checkpoints")).andExpect(status().isUnauthorized());
    }

    @Test
    void archiveWithoutCredentialsIsRejected() throws Exception {
        mvc.perform(post("/audit/archive")).andExpect(status().isUnauthorized());
    }

    @Test
    void badPasswordIsRejected() throws Exception {
        mvc.perform(get("/audit/verify")
                        .with(org.springframework.security.test.web.servlet.request
                                .SecurityMockMvcRequestPostProcessors.httpBasic("reader", "wrong-password")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void unknownUserIsRejected() throws Exception {
        mvc.perform(get("/audit/verify")
                        .with(org.springframework.security.test.web.servlet.request
                                .SecurityMockMvcRequestPostProcessors.httpBasic("nobody", "whatever")))
                .andExpect(status().isUnauthorized());
    }

    // ---------------------------------------------------------------
    // Authorization - authenticated, wrong role
    // ---------------------------------------------------------------

    @Test
    void readerCannotAppend() throws Exception {
        mvc.perform(post("/audit").with(asReader()).contentType(MediaType.APPLICATION_JSON)
                        .content(eventBody("X", "1")))
                .andExpect(status().isForbidden());
        assertThat(recordRepository.count()).isZero();
    }

    @Test
    void writerCannotQuery() throws Exception {
        mvc.perform(get("/audit").with(asWriter())).andExpect(status().isForbidden());
    }

    @Test
    void writerCannotVerify() throws Exception {
        mvc.perform(get("/audit/verify").with(asWriter())).andExpect(status().isForbidden());
    }

    @Test
    void writerCannotRedact() throws Exception {
        mvc.perform(post("/audit/{id}/redact", UUID.randomUUID()).with(asWriter())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fieldPath\":\"/x\",\"reason\":\"r\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void readerCannotRedact() throws Exception {
        mvc.perform(post("/audit/{id}/redact", UUID.randomUUID()).with(asReader())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fieldPath\":\"/x\",\"reason\":\"r\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void readerCannotExport() throws Exception {
        mvc.perform(get("/audit/export").with(asReader()).param("actorId", ADVISOR_17))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("a writer cannot export even its own data - export is evidentiary, not ownership-based")
    void writerCannotExport() throws Exception {
        mvc.perform(get("/audit/export").with(asWriter()).param("actorId", ADVISOR_17))
                .andExpect(status().isForbidden());
    }

    @Test
    void writerCannotTriggerRetention() throws Exception {
        mvc.perform(post("/audit/retention/run").with(asWriter())).andExpect(status().isForbidden());
    }

    @Test
    void readerCannotTriggerRetention() throws Exception {
        mvc.perform(post("/audit/retention/run").with(asReader())).andExpect(status().isForbidden());
    }

    @Test
    void readerCannotArchive() throws Exception {
        mvc.perform(post("/audit/archive").with(asReader())).andExpect(status().isForbidden());
    }

    @Test
    void readerCannotCreateCheckpoint() throws Exception {
        mvc.perform(post("/audit/checkpoints").with(asReader())).andExpect(status().isForbidden());
    }

    @Test
    void writerCannotListCheckpoints() throws Exception {
        mvc.perform(get("/audit/checkpoints").with(asWriter())).andExpect(status().isForbidden());
    }

    // ---------------------------------------------------------------
    // Ownership over HTTP
    // ---------------------------------------------------------------

    @Test
    void writerCanAppendAndIsStampedWithItsBoundActor() throws Exception {
        mvc.perform(post("/audit").with(asWriter()).contentType(MediaType.APPLICATION_JSON)
                        .content(eventBody("X", "1")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.actorId").value(ADVISOR_17))
                .andExpect(jsonPath("$.tenantId").value(TENANT_A));
    }

    @Test
    void readerCannotQueryAnotherActorsData() throws Exception {
        mvc.perform(get("/audit").with(asReader()).param("actorId", ADVISOR_99))
                .andExpect(status().isForbidden());
    }

    @Test
    void readerQueryWithNoFilterIsScopedToItsOwnActor() throws Exception {
        mvc.perform(post("/audit").with(asWriter()).contentType(MediaType.APPLICATION_JSON)
                        .content(eventBody("OWN", "1"))).andExpect(status().isCreated());
        mvc.perform(post("/audit").with(asAdmin()).contentType(MediaType.APPLICATION_JSON)
                        .content(eventBody("OTHER", "2"))).andExpect(status().isCreated());

        mvc.perform(get("/audit").with(asReader()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].actorId").value(ADVISOR_17))
                .andExpect(jsonPath("$.content[0].eventType").value("OWN"));
    }

    @Test
    @DisplayName("a denial says nothing about what exists")
    void forbiddenResponseDoesNotLeakDetail() throws Exception {
        mvc.perform(get("/audit").with(asReader()).param("actorId", ADVISOR_99))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.detail")
                        .value("You are not authorized to perform this operation on this data"));
    }

    // ---------------------------------------------------------------
    // Idempotency / replay over HTTP
    // ---------------------------------------------------------------

    @Test
    @DisplayName("replaying an append with the same Idempotency-Key returns the original record")
    void replayWithSameKeyReturnsOriginal() throws Exception {
        String first = mvc.perform(post("/audit").with(asWriter()).header("Idempotency-Key", "key-1")
                        .contentType(MediaType.APPLICATION_JSON).content(eventBody("X", "1")))
                .andExpect(status().isCreated())
                .andExpect(header().string("Idempotent-Replay", "false"))
                .andReturn().getResponse().getContentAsString();

        String replay = mvc.perform(post("/audit").with(asWriter()).header("Idempotency-Key", "key-1")
                        .contentType(MediaType.APPLICATION_JSON).content(eventBody("X", "1")))
                .andExpect(status().isOk())
                .andExpect(header().string("Idempotent-Replay", "true"))
                .andReturn().getResponse().getContentAsString();

        assertThat(mapper.readTree(replay).get("id")).isEqualTo(mapper.readTree(first).get("id"));
        assertThat(recordRepository.count()).isEqualTo(1);
    }

    @Test
    @DisplayName("reusing an Idempotency-Key with a different body is a conflict, not a silent replay")
    void reusingKeyWithDifferentBodyIsConflict() throws Exception {
        mvc.perform(post("/audit").with(asWriter()).header("Idempotency-Key", "key-2")
                        .contentType(MediaType.APPLICATION_JSON).content(eventBody("X", "1")))
                .andExpect(status().isCreated());

        mvc.perform(post("/audit").with(asWriter()).header("Idempotency-Key", "key-2")
                        .contentType(MediaType.APPLICATION_JSON).content(eventBody("DIFFERENT", "1")))
                .andExpect(status().isConflict());

        assertThat(recordRepository.count()).isEqualTo(1);
    }

    @Test
    @DisplayName("without a key, two identical requests are two distinct events")
    void withoutKeyIdenticalRequestsAreDistinct() throws Exception {
        mvc.perform(post("/audit").with(asWriter()).contentType(MediaType.APPLICATION_JSON)
                        .content(eventBody("X", "1"))).andExpect(status().isCreated());
        mvc.perform(post("/audit").with(asWriter()).contentType(MediaType.APPLICATION_JSON)
                        .content(eventBody("X", "1"))).andExpect(status().isCreated());

        assertThat(recordRepository.count()).isEqualTo(2);
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private void appendAsAdmin(String eventType, String resourceId) throws Exception {
        mvc.perform(post("/audit").with(asAdmin()).contentType(MediaType.APPLICATION_JSON)
                        .content(eventBody(eventType, resourceId)))
                .andExpect(status().isCreated());
    }

}
