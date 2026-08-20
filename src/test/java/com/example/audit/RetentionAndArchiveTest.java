package com.example.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The retention lifecycle, its authorization, and the guarantee that archiving cannot
 * damage integrity.
 *
 * <p>Archiving an audit record is where a retention feature usually goes wrong: the
 * obvious implementation deletes rows, which in a hash-chained log destroys the evidence
 * it was supposed to manage. Here archiving is a flag on a field no hash covers, and
 * these tests assert the consequence directly - the chain still verifies afterwards, and
 * archived records still export and still verify inside the bundle.
 */
class RetentionAndArchiveTest extends AbstractAuditTest {

    private String eventBodyDated(String eventType, String resourceId, Instant timestamp) {
        return "{\"eventType\":\"" + eventType + "\",\"resourceType\":\"ACCOUNT\",\"resourceId\":\""
                + resourceId + "\",\"payload\":{\"ok\":true},\"timestamp\":\"" + timestamp + "\"}";
    }

    private void appendDated(String eventType, String resourceId, Instant timestamp) throws Exception {
        mvc.perform(post("/audit").with(asWriter()).contentType(MediaType.APPLICATION_JSON)
                        .content(eventBodyDated(eventType, resourceId, timestamp)))
                .andExpect(status().isCreated());
    }

    @Test
    @DisplayName("archiving marks only records past the cutoff")
    void archiveAppliesTheAgeCutoff() throws Exception {
        appendDated("OLD", "r-old", Instant.now().minus(400, ChronoUnit.DAYS));
        appendDated("RECENT", "r-recent", Instant.now().minus(1, ChronoUnit.DAYS));

        mvc.perform(post("/audit/archive").with(asAdmin()).param("olderThanDays", "30"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.archivedCount").value(1))
                .andExpect(jsonPath("$.chainStillIntact").value(true));

        assertThat(recordRepository.findByTenantIdOrderByChainIndexAsc(TENANT_A))
                .satisfiesExactly(
                        old -> assertThat(old.isArchived()).isTrue(),
                        recent -> assertThat(recent.isArchived()).isFalse());
    }

    @Test
    @DisplayName("archived records are hidden from ordinary queries and returned on request")
    void archivedRecordsAreExcludedUnlessAskedFor() throws Exception {
        appendDated("OLD", "r-old", Instant.now().minus(400, ChronoUnit.DAYS));
        appendDated("RECENT", "r-recent", Instant.now().minus(1, ChronoUnit.DAYS));
        mvc.perform(post("/audit/archive").with(asAdmin()).param("olderThanDays", "30"))
                .andExpect(status().isOk());

        mvc.perform(get("/audit").with(asReader()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].eventType").value("RECENT"));

        mvc.perform(get("/audit").with(asReader()).param("includeArchived", "true"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(2));
    }

    @Test
    @DisplayName("the chain still verifies after archiving, and archived records are still counted")
    void archivingPreservesVerifiability() throws Exception {
        appendDated("A", "r-1", Instant.now().minus(400, ChronoUnit.DAYS));
        appendDated("B", "r-2", Instant.now().minus(399, ChronoUnit.DAYS));
        appendDated("C", "r-3", Instant.now().minus(1, ChronoUnit.DAYS));

        mvc.perform(post("/audit/archive").with(asAdmin()).param("olderThanDays", "30"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.archivedCount").value(2));

        // Verification deliberately covers archived rows too - skipping them would leave
        // an archived record modifiable without detection.
        mvc.perform(get("/audit/verify").with(asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(true))
                .andExpect(jsonPath("$.checkedRecords").value(3));
    }

    @Test
    @DisplayName("tampering with an archived record is still detected")
    void tamperingWithAnArchivedRecordIsDetected() throws Exception {
        appendDated("A", "r-1", Instant.now().minus(400, ChronoUnit.DAYS));
        mvc.perform(post("/audit/archive").with(asAdmin()).param("olderThanDays", "30"))
                .andExpect(status().isOk());

        var record = recordRepository.findByTenantIdOrderByChainIndexAsc(TENANT_A).get(0);
        record.setPayloadJson("{\"ok\":false}");
        recordRepository.saveAndFlush(record);

        mvc.perform(get("/audit/verify").with(asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(false))
                .andExpect(jsonPath("$.violationType").value("PAYLOAD_OR_REDACTION_LEDGER_MISMATCH"));
    }

    @Test
    @DisplayName("archiving is idempotent - a second sweep finds nothing left to do")
    void archivingTwiceIsIdempotent() throws Exception {
        appendDated("A", "r-1", Instant.now().minus(400, ChronoUnit.DAYS));

        mvc.perform(post("/audit/archive").with(asAdmin()).param("olderThanDays", "30"))
                .andExpect(jsonPath("$.archivedCount").value(1));
        mvc.perform(post("/audit/archive").with(asAdmin()).param("olderThanDays", "30"))
                .andExpect(jsonPath("$.archivedCount").value(0));
    }

    @Test
    @DisplayName("the retention endpoint reports its tenant and leaves the chain intact")
    void retentionRunReportsTenantAndIntegrity() throws Exception {
        appendDated("A", "r-1", Instant.now().minus(400, ChronoUnit.DAYS));

        mvc.perform(post("/audit/retention/run").with(asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.archivedCount").value(1))
                .andExpect(jsonPath("$.tenantId").value(TENANT_A))
                .andExpect(jsonPath("$.chainStillIntact").value(true))
                .andExpect(jsonPath("$.ranAt").isNotEmpty());
    }

    @Test
    @DisplayName("retention never deletes an audit record")
    void retentionNeverDeletes() throws Exception {
        appendDated("A", "r-1", Instant.now().minus(4000, ChronoUnit.DAYS));
        long before = recordRepository.count();

        mvc.perform(post("/audit/retention/run").with(asAdmin())).andExpect(status().isOk());
        mvc.perform(post("/audit/archive").with(asAdmin()).param("olderThanDays", "0"))
                .andExpect(status().isOk());

        assertThat(recordRepository.count()).isEqualTo(before);
    }

    @Test
    @DisplayName("a negative archive age is rejected")
    void negativeArchiveAgeIsRejected() throws Exception {
        mvc.perform(post("/audit/archive").with(asAdmin()).param("olderThanDays", "-5"))
                .andExpect(status().isBadRequest());
    }
}
