package com.example.audit;

import com.example.audit.domain.AuditRecord;
import com.example.audit.repository.AuditRecordRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Covers the full write-query-verify-redact-tamper-export story, authenticated as
 * {@code admin} (who holds every role) so these assertions stay focused on audit-log
 * behavior rather than on the authentication/authorization boundary, which has its own
 * dedicated suite in {@link AuditSecurityTest}.
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
class AuditLogIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired AuditRecordRepository repository;

    private static RequestPostProcessor asAdmin() {
        return SecurityMockMvcRequestPostProcessors.httpBasic("admin", "admin-dev-pass");
    }

    @Test
    void appendQueryVerifyRedactAndDetectDirectTampering() throws Exception {
        String body = """
                {"eventType":"CLIENT_DATA_ACCESSED","actorId":"advisor-17","resourceType":"ACCOUNT",
                 "resourceId":"acct-100","payload":{"accountNumber":"123456789","purpose":"support"}}
                """;
        String response = mvc.perform(post("/audit").with(asAdmin()).contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.recordHash").isNotEmpty())
                .andReturn().getResponse().getContentAsString();
        UUID id = UUID.fromString(mapper.readTree(response).get("id").asText());

        mvc.perform(get("/audit").with(asAdmin()).param("actorId", "advisor-17"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1));
        mvc.perform(get("/audit/verify").with(asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(true));

        mvc.perform(post("/audit/{id}/redact", id).with(asAdmin()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fieldPath\":\"/accountNumber\",\"reason\":\"privacy request\",\"actorId\":\"privacy-ops\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.replacement").value("[REDACTED]"));
        mvc.perform(get("/audit/verify").with(asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(true));

        AuditRecord record = repository.findById(id).orElseThrow();
        JsonNode altered = mapper.readTree(record.getPayloadJson());
        ((com.fasterxml.jackson.databind.node.ObjectNode) altered).put("purpose", "tampered");
        record.setPayloadJson(mapper.writeValueAsString(altered));
        repository.saveAndFlush(record);

        mvc.perform(get("/audit/verify").with(asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(false))
                .andExpect(jsonPath("$.violationType").value("PAYLOAD_OR_REDACTION_LEDGER_MISMATCH"));
    }

    @Test
    void exportContainsSignedContiguousProofSegment() throws Exception {
        append("A", "actor-a", "resource-1");
        append("B", "actor-b", "resource-2");
        append("C", "actor-a", "resource-3");

        String json = mvc.perform(get("/audit/export").with(asAdmin()).param("actorId", "actor-a"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.manifestHash").isNotEmpty())
                .andExpect(jsonPath("$.signatureBase64").isNotEmpty())
                .andReturn().getResponse().getContentAsString();
        JsonNode root = mapper.readTree(json);
        assertThat(root.get("records").size()).isGreaterThanOrEqualTo(3);
    }

    private void append(String type, String actor, String resource) throws Exception {
        mvc.perform(post("/audit").with(asAdmin()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"eventType\":\"" + type + "\",\"actorId\":\"" + actor
                                + "\",\"resourceType\":\"ACCOUNT\",\"resourceId\":\"" + resource
                                + "\",\"payload\":{\"ok\":true}}"))
                .andExpect(status().isCreated());
    }
}
