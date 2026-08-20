package com.example.audit;

import com.example.audit.domain.ChainCheckpoint;
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
 * Signed checkpoints, and the attack they exist to catch.
 *
 * <p>Hash chaining detects edits and reordering, but it is satisfied by any internally
 * consistent chain. An attacker with database access can delete the most recent records
 * and the remainder still links perfectly - {@code intact=true}, evidence quietly gone.
 * A signed commitment to (index, recordHash) is external to the data being checked, so
 * that attack fails. These tests demonstrate both halves: the truncation that plain link
 * checking misses, and the checkpoint catching it.
 */
class CheckpointIntegrityTest extends AbstractAuditTest {

    private void appendAsAdmin(String eventType, String resourceId) throws Exception {
        mvc.perform(post("/audit").with(asAdmin()).contentType(MediaType.APPLICATION_JSON)
                        .content(eventBody(eventType, resourceId)))
                .andExpect(status().isCreated());
    }

    @Test
    @DisplayName("a checkpoint commits to the current head and verification still passes")
    void checkpointOverAnIntactChainVerifies() throws Exception {
        appendAsAdmin("A", "r-1");
        appendAsAdmin("B", "r-2");

        mvc.perform(post("/audit/checkpoints").with(asAdmin()))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.chainIndex").value(2))
                .andExpect(jsonPath("$.tenantId").value(TENANT_A))
                .andExpect(jsonPath("$.signatureBase64").isNotEmpty())
                .andExpect(jsonPath("$.keyId").isNotEmpty());

        mvc.perform(get("/audit/verify").with(asAdmin()))
                .andExpect(jsonPath("$.intact").value(true));
        mvc.perform(get("/audit/checkpoints").with(asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1));
    }

    @Test
    @DisplayName("truncating the chain is invisible to link checking but caught by a checkpoint")
    void truncationIsCaughtOnlyByTheCheckpoint() throws Exception {
        appendAsAdmin("A", "r-1");
        appendAsAdmin("B", "r-2");
        appendAsAdmin("C", "r-3");
        mvc.perform(post("/audit/checkpoints").with(asAdmin())).andExpect(status().isCreated());

        // Delete the tail. Records 1 and 2 still link to each other perfectly.
        var chain = recordRepository.findByTenantIdOrderByChainIndexAsc(TENANT_A);
        recordRepository.delete(chain.get(2));
        recordRepository.flush();

        mvc.perform(get("/audit/verify").with(asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(false))
                .andExpect(jsonPath("$.violationType").value("CHECKPOINT_MISSING_RECORDS"))
                .andExpect(jsonPath("$.firstInconsistentChainIndex").value(3));
    }

    @Test
    @DisplayName("a chain rebuilt to a different history fails its checkpoint")
    void rewrittenHistoryFailsTheCheckpoint() throws Exception {
        appendAsAdmin("ORIGINAL", "r-1");
        mvc.perform(post("/audit/checkpoints").with(asAdmin())).andExpect(status().isCreated());

        // Wipe the chain and rebuild it with different content. The new chain is
        // internally flawless - only the checkpoint remembers what index 1 used to be.
        recordRepository.deleteAll();
        chainHeadRepository.deleteAll();
        recordRepository.flush();
        appendAsAdmin("SUBSTITUTED", "r-1");

        mvc.perform(get("/audit/verify").with(asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(false))
                .andExpect(jsonPath("$.violationType").value("CHECKPOINT_MISMATCH"));
    }

    @Test
    @DisplayName("a forged checkpoint is rejected because its signature does not verify")
    void forgedCheckpointIsRejected() throws Exception {
        appendAsAdmin("A", "r-1");
        var record = recordRepository.findByTenantIdOrderByChainIndexAsc(TENANT_A).get(0);

        // An attacker inserts a checkpoint directly, without the signing key.
        checkpointRepository.saveAndFlush(new ChainCheckpoint(TENANT_A, record.getChainIndex(),
                record.getRecordHash(), Instant.now().truncatedTo(ChronoUnit.MILLIS), "test-key",
                java.util.Base64.getEncoder().encodeToString(new byte[64])));

        mvc.perform(get("/audit/verify").with(asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(false))
                .andExpect(jsonPath("$.violationType").value("CHECKPOINT_SIGNATURE_INVALID"));
    }

    @Test
    @DisplayName("checkpointing an empty tenant chain is rejected")
    void checkpointOnAnEmptyChainIsRejected() throws Exception {
        mvc.perform(post("/audit/checkpoints").with(asAdmin()))
                .andExpect(status().isBadRequest());
        assertThat(checkpointRepository.count()).isZero();
    }

    @Test
    @DisplayName("appending after a checkpoint keeps the chain verifiable")
    void appendingAfterACheckpointStillVerifies() throws Exception {
        appendAsAdmin("A", "r-1");
        mvc.perform(post("/audit/checkpoints").with(asAdmin())).andExpect(status().isCreated());
        appendAsAdmin("B", "r-2");
        appendAsAdmin("C", "r-3");

        mvc.perform(get("/audit/verify").with(asAdmin()))
                .andExpect(jsonPath("$.intact").value(true))
                .andExpect(jsonPath("$.checkedRecords").value(3));
    }
}
