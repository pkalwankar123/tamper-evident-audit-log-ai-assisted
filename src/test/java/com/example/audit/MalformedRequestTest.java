package com.example.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Malformed input, boundaries and abuse cases.
 *
 * <p>Each test asserts the state as well as the status where a bad request could
 * plausibly have written something - a 400 that still appended a record would be worse
 * than a 500.
 */
class MalformedRequestTest extends AbstractAuditTest {

    // ---------------------------------------------------------------
    // Body validation
    // ---------------------------------------------------------------

    @Test
    void missingEventTypeIsRejected() throws Exception {
        mvc.perform(post("/audit").with(asWriter()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"resourceType\":\"ACCOUNT\",\"resourceId\":\"1\",\"payload\":{}}"))
                .andExpect(status().isBadRequest());
        assertThat(recordRepository.count()).isZero();
    }

    @Test
    void blankEventTypeIsRejected() throws Exception {
        mvc.perform(post("/audit").with(asWriter()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"eventType\":\"   \",\"resourceType\":\"ACCOUNT\",\"resourceId\":\"1\","
                                + "\"payload\":{}}"))
                .andExpect(status().isBadRequest());
        assertThat(recordRepository.count()).isZero();
    }

    @Test
    void missingPayloadIsRejected() throws Exception {
        mvc.perform(post("/audit").with(asWriter()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"eventType\":\"X\",\"resourceType\":\"ACCOUNT\",\"resourceId\":\"1\"}"))
                .andExpect(status().isBadRequest());
        assertThat(recordRepository.count()).isZero();
    }

    @Test
    void unparseableJsonIsRejected() throws Exception {
        mvc.perform(post("/audit").with(asWriter()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"eventType\":\"X\",,,"))
                .andExpect(status().isBadRequest());
        assertThat(recordRepository.count()).isZero();
    }

    @Test
    void emptyBodyIsRejected() throws Exception {
        mvc.perform(post("/audit").with(asWriter()).contentType(MediaType.APPLICATION_JSON).content(""))
                .andExpect(status().isBadRequest());
    }

    @Test
    void wrongContentTypeIsRejected() throws Exception {
        mvc.perform(post("/audit").with(asWriter()).contentType(MediaType.TEXT_PLAIN)
                        .content(eventBody("X", "1")))
                .andExpect(status().isUnsupportedMediaType());
    }

    @Test
    @DisplayName("over-long field values are rejected at the boundary, not truncated into the chain")
    void overlongFieldValuesAreRejected() throws Exception {
        String longValue = "x".repeat(300);
        mvc.perform(post("/audit").with(asWriter()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"eventType\":\"" + longValue + "\",\"resourceType\":\"ACCOUNT\","
                                + "\"resourceId\":\"1\",\"payload\":{}}"))
                .andExpect(status().isBadRequest());
        assertThat(recordRepository.count()).isZero();
    }

    // ---------------------------------------------------------------
    // Size limits
    // ---------------------------------------------------------------

    @Test
    @DisplayName("an oversized payload is refused with 413 and appends nothing")
    void oversizedPayloadIsRejected() throws Exception {
        String big = "x".repeat(70_000);
        mvc.perform(post("/audit").with(asWriter()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"eventType\":\"X\",\"resourceType\":\"ACCOUNT\",\"resourceId\":\"1\","
                                + "\"payload\":{\"blob\":\"" + big + "\"}}"))
                .andExpect(status().isPayloadTooLarge());
        assertThat(recordRepository.count()).isZero();
        // Not even a chain head is created for a request that never became a record.
        assertThat(chainHeadRepository.findById(TENANT_A))
                .satisfiesAnyOf(
                        head -> assertThat(head).isEmpty(),
                        head -> assertThat(head.orElseThrow().getLastIndex()).isZero());
    }

    @Test
    @DisplayName("a payload just under the limit is accepted, proving the boundary is not off by orders of magnitude")
    void payloadJustUnderTheLimitIsAccepted() throws Exception {
        String value = "x".repeat(60_000);
        mvc.perform(post("/audit").with(asWriter()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"eventType\":\"X\",\"resourceType\":\"ACCOUNT\",\"resourceId\":\"1\","
                                + "\"payload\":{\"blob\":\"" + value + "\"}}"))
                .andExpect(status().isCreated());
        assertThat(recordRepository.count()).isEqualTo(1);
    }

    @Test
    void oversizedIdempotencyKeyIsRejected() throws Exception {
        mvc.perform(post("/audit").with(asWriter()).header("Idempotency-Key", "k".repeat(500))
                        .contentType(MediaType.APPLICATION_JSON).content(eventBody("X", "1")))
                .andExpect(status().isBadRequest());
        assertThat(recordRepository.count()).isZero();
    }

    // ---------------------------------------------------------------
    // Pagination and query parameter boundaries
    // ---------------------------------------------------------------

    @Test
    void negativePageIsRejected() throws Exception {
        mvc.perform(get("/audit").with(asReader()).param("page", "-1")).andExpect(status().isBadRequest());
    }

    @Test
    void zeroPageSizeIsRejected() throws Exception {
        mvc.perform(get("/audit").with(asReader()).param("size", "0")).andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("an over-large page size is refused rather than silently clamped")
    void oversizedPageSizeIsRejected() throws Exception {
        mvc.perform(get("/audit").with(asReader()).param("size", "5000")).andExpect(status().isBadRequest());
    }

    @Test
    void maximumPageSizeIsAccepted() throws Exception {
        mvc.perform(get("/audit").with(asReader()).param("size", "500")).andExpect(status().isOk());
    }

    @Test
    void nonNumericPaginationIsRejected() throws Exception {
        mvc.perform(get("/audit").with(asReader()).param("page", "abc")).andExpect(status().isBadRequest());
        mvc.perform(get("/audit").with(asReader()).param("size", "1e9")).andExpect(status().isBadRequest());
    }

    @Test
    void invertedTimeRangeIsRejected() throws Exception {
        mvc.perform(get("/audit").with(asReader())
                        .param("from", "2026-01-02T00:00:00Z")
                        .param("to", "2026-01-01T00:00:00Z"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void malformedTimestampIsRejected() throws Exception {
        mvc.perform(get("/audit").with(asReader()).param("from", "not-a-timestamp"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void malformedUuidPathIsRejected() throws Exception {
        mvc.perform(get("/audit/{id}", "not-a-uuid").with(asReader())).andExpect(status().isBadRequest());
    }

    // ---------------------------------------------------------------
    // Redaction edge cases
    // ---------------------------------------------------------------

    @Test
    void redactingAnUnknownRecordIsNotFound() throws Exception {
        mvc.perform(post("/audit/{id}/redact", UUID.randomUUID()).with(asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fieldPath\":\"/x\",\"reason\":\"r\"}"))
                .andExpect(status().isNotFound());
    }

    @Test
    void redactingAMissingFieldIsRejected() throws Exception {
        String created = mvc.perform(post("/audit").with(asAdmin()).contentType(MediaType.APPLICATION_JSON)
                        .content(eventBody("X", "1")))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        UUID id = UUID.fromString(mapper.readTree(created).get("id").asText());

        mvc.perform(post("/audit/{id}/redact", id).with(asAdmin()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fieldPath\":\"/does-not-exist\",\"reason\":\"r\"}"))
                .andExpect(status().isBadRequest());
        assertThat(redactionRepository.count()).isZero();
    }

    @Test
    void redactionRequiresAReason() throws Exception {
        mvc.perform(post("/audit/{id}/redact", UUID.randomUUID()).with(asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fieldPath\":\"/x\",\"reason\":\"\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("a malformed JSON Pointer is rejected")
    void malformedJsonPointerIsRejected() throws Exception {
        String created = mvc.perform(post("/audit").with(asAdmin()).contentType(MediaType.APPLICATION_JSON)
                        .content(eventBody("X", "1")))
                .andReturn().getResponse().getContentAsString();
        UUID id = UUID.fromString(mapper.readTree(created).get("id").asText());

        mvc.perform(post("/audit/{id}/redact", id).with(asAdmin()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fieldPath\":\"no-leading-slash\",\"reason\":\"r\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("a path-traversal attempt is refused outright, before any handler")
    void pathTraversalIsRefused() throws Exception {
        // Rejected as a malformed path rather than resolved and then authorized - the
        // request never reaches a handler, so there is nothing to authorize against.
        mvc.perform(get("/audit/../actuator/env")).andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("an unknown route still demands authentication and does not confirm it is unknown")
    void unknownRouteStillRequiresAuthentication() throws Exception {
        mvc.perform(get("/definitely-not-a-route")).andExpect(status().isUnauthorized());
        mvc.perform(get("/audit/checkpoints/anything")).andExpect(status().isUnauthorized());
    }
}
