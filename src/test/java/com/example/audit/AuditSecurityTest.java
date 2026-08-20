package com.example.audit;

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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Dedicated authentication/authorization boundary suite for every {@code /audit/**}
 * endpoint, kept separate from {@link AuditLogIntegrationTest} so security coverage is
 * an explicit, independently reviewable artifact rather than incidental assertions
 * inside the functional test.
 *
 * <p>Matrix covered per role-guarded endpoint:
 * <ul>
 *   <li>no credentials -&gt; 401 (authentication)</li>
 *   <li>correct credentials, wrong role -&gt; 403 (authorization)</li>
 *   <li>correct credentials, correct role -&gt; 2xx (authorization)</li>
 * </ul>
 *
 * <p>Enforcement point under test is {@code SecurityConfig}'s
 * {@code SecurityFilterChain} - see {@code docs/ARCHITECTURE.md} for the role model and
 * {@code docs/TESTING.md} for what is and is not covered by this suite (e.g. password
 * strength, brute-force protection, and session/token expiry are explicit prototype
 * boundaries, not gaps in this file).
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
class AuditSecurityTest {

    @Autowired MockMvc mvc;

    private static RequestPostProcessor asWriter() {
        return SecurityMockMvcRequestPostProcessors.httpBasic(
                "writer", "test-writer-password");
    }

    private static RequestPostProcessor asReader() {
        return SecurityMockMvcRequestPostProcessors.httpBasic(
                "reader", "test-reader-password");
    }

    private static RequestPostProcessor asAdmin() {
        return SecurityMockMvcRequestPostProcessors.httpBasic(
                "admin", "test-admin-password");
    }

    // ---------------------------------------------------------------------
    // Authentication - no credentials at all (expect 401) for every
    // role-guarded endpoint, including the redact route.
    // ---------------------------------------------------------------------

    @Test
    void appendWithoutCredentialsIsRejected() throws Exception {
        mvc.perform(post("/audit").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"eventType\":\"X\",\"actorId\":\"a\",\"resourceType\":\"T\",\"resourceId\":\"1\",\"payload\":{}}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void queryWithoutCredentialsIsRejected() throws Exception {
        mvc.perform(get("/audit"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void verifyWithoutCredentialsIsRejected() throws Exception {
        mvc.perform(get("/audit/verify"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void redactWithoutCredentialsIsRejected() throws Exception {
        String id = UUID.randomUUID().toString();
        mvc.perform(post("/audit/{id}/redact", id).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fieldPath\":\"/x\",\"reason\":\"r\",\"actorId\":\"a\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void exportWithoutCredentialsIsRejected() throws Exception {
        mvc.perform(get("/audit/export").param("actorId", "advisor-17"))
                .andExpect(status().isUnauthorized());
    }

    // ---------------------------------------------------------------------
    // Authorization - authenticated, but wrong role for the action (expect 403)
    // ---------------------------------------------------------------------

    @Test
    void readerCannotAppend() throws Exception {
        mvc.perform(post("/audit").with(asReader()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"eventType\":\"X\",\"actorId\":\"a\",\"resourceType\":\"T\",\"resourceId\":\"1\",\"payload\":{}}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void writerCannotQuery() throws Exception {
        // Writer holds ROLE_AUDIT_WRITER only - append access does not imply read access.
        mvc.perform(get("/audit").with(asWriter()))
                .andExpect(status().isForbidden());
    }

    @Test
    void writerCannotVerify() throws Exception {
        mvc.perform(get("/audit/verify").with(asWriter()))
                .andExpect(status().isForbidden());
    }

    @Test
    void writerCannotRedact() throws Exception {
        String id = UUID.randomUUID().toString();
        mvc.perform(post("/audit/{id}/redact", id).with(asWriter()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fieldPath\":\"/x\",\"reason\":\"r\",\"actorId\":\"a\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void readerCannotRedact() throws Exception {
        // Redaction is a high-impact, privacy-affecting action - reader (read-only) must not
        // be able to perform it, even though reader CAN read the data being redacted.
        String id = UUID.randomUUID().toString();
        mvc.perform(post("/audit/{id}/redact", id).with(asReader()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fieldPath\":\"/x\",\"reason\":\"r\",\"actorId\":\"a\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void readerCannotExport() throws Exception {
        // Export is treated as high-impact (produces a distributable, signed evidentiary
        // bundle) so it requires admin, not merely read access.
        mvc.perform(get("/audit/export").with(asReader()).param("actorId", "advisor-17"))
                .andExpect(status().isForbidden());
    }

    // ---------------------------------------------------------------------
    // Authorization - correct role succeeds
    // ---------------------------------------------------------------------

    @Test
    void writerCanAppend() throws Exception {
        mvc.perform(post("/audit").with(asWriter()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"eventType\":\"X\",\"actorId\":\"a\",\"resourceType\":\"T\",\"resourceId\":\"1\",\"payload\":{}}"))
                .andExpect(status().isCreated());
    }

    @Test
    void readerCanQueryAndVerify() throws Exception {
        mvc.perform(post("/audit").with(asAdmin()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"eventType\":\"X\",\"actorId\":\"a\",\"resourceType\":\"T\",\"resourceId\":\"1\",\"payload\":{}}"))
                .andExpect(status().isCreated());

        mvc.perform(get("/audit").with(asReader()))
                .andExpect(status().isOk());
        mvc.perform(get("/audit/verify").with(asReader()))
                .andExpect(status().isOk());
    }

    @Test
    void adminCanRedact() throws Exception {
        String response = mvc.perform(post("/audit").with(asAdmin()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"eventType\":\"X\",\"actorId\":\"a\",\"resourceType\":\"T\",\"resourceId\":\"1\","
                                + "\"payload\":{\"secret\":\"value\"}}"))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        String id = response.substring(response.indexOf("\"id\":\"") + 6);
        id = id.substring(0, id.indexOf('"'));

        mvc.perform(post("/audit/{id}/redact", id).with(asAdmin()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fieldPath\":\"/secret\",\"reason\":\"privacy request\",\"actorId\":\"privacy-ops\"}"))
                .andExpect(status().isOk());
    }

    @Test
    void adminCanExport() throws Exception {
        mvc.perform(post("/audit")
                .with(asAdmin())
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "eventType": "X",
                      "resourceType": "T",
                      "resourceId": "1",
                      "payload": {}
                    }
                    """))
                .andExpect(status().isCreated());

        mvc.perform(get("/audit/export")
                .with(asAdmin())
                .param("actorId", "admin-a"))
                .andExpect(status().isOk());
    }

    // ---------------------------------------------------------------------
    // API docs remain public (demo/local convenience - see README production boundaries)
    // ---------------------------------------------------------------------

    @Test
    void apiDocsAreAccessibleWithoutCredentials() throws Exception {
        mvc.perform(get("/v3/api-docs"))
                .andExpect(status().isOk());
    }

    @Test
    void swaggerUiIsAccessibleWithoutCredentials() throws Exception {
        mvc.perform(get("/swagger-ui/index.html"))
                .andExpect(status().isOk());
    }
}
