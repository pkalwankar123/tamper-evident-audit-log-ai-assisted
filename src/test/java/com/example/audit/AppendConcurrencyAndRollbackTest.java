package com.example.audit;

import com.example.audit.api.ApiModels;
import com.example.audit.domain.AuditRecord;
import com.example.audit.repository.AuditRecordRepository;
import com.example.audit.repository.ChainCheckpointRepository;
import com.example.audit.repository.ChainHeadRepository;
import com.example.audit.repository.IdempotencyRecordRepository;
import com.example.audit.repository.RedactionEntryRepository;
import com.example.audit.security.AuthenticatedActor;
import com.example.audit.service.AuditService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Concurrent appends and the rollback behaviour underneath them.
 *
 * <p>The rollback case is the one that used to be untested and is the more important of
 * the two: if a failed append could consume a chain index, the very next successful
 * append would leave a permanent gap, and every subsequent verification of that tenant
 * would report tampering that never happened. Serializing on the database chain-head row
 * inside the same transaction as the insert is what prevents it, and this asserts the
 * outcome rather than the mechanism.
 */
@SpringBootTest
class AppendConcurrencyAndRollbackTest {

    @Autowired AuditService auditService;
    @Autowired ObjectMapper mapper;
    @Autowired ChainHeadRepository chainHeadRepository;
    @Autowired RedactionEntryRepository redactionRepository;
    @Autowired ChainCheckpointRepository checkpointRepository;
    @Autowired IdempotencyRecordRepository idempotencyRepository;

    @SpyBean AuditRecordRepository recordRepository;

    private static final AuthenticatedActor ACTOR =
            new AuthenticatedActor("writer", "actor-concurrent", "tenant-a", false);

    @BeforeEach
    void reset() {
        Mockito.reset(recordRepository);
        redactionRepository.deleteAll();
        checkpointRepository.deleteAll();
        idempotencyRepository.deleteAll();
        recordRepository.deleteAll();
        chainHeadRepository.deleteAll();
    }

    private ApiModels.CreateAuditEventRequest request(String resourceId) throws Exception {
        return new ApiModels.CreateAuditEventRequest("EVT", "ACCOUNT", resourceId,
                mapper.readTree("{\"n\":1}"), null);
    }

    @Test
    @DisplayName("concurrent appends produce a contiguous, gap-free, verifiable chain")
    void concurrentAppendsProduceAContiguousChain() throws Exception {
        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger failures = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            int index = i;
            pool.submit(() -> {
                try {
                    ready.countDown();
                    go.await();
                    auditService.append(ACTOR, request("r-" + index), null);
                } catch (Exception exception) {
                    failures.incrementAndGet();
                }
            });
        }
        assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
        go.countDown();
        pool.shutdown();
        assertThat(pool.awaitTermination(30, TimeUnit.SECONDS)).isTrue();

        assertThat(failures.get()).isZero();

        List<AuditRecord> all = recordRepository.findByTenantIdOrderByChainIndexAsc("tenant-a");
        List<Long> indices = all.stream().map(AuditRecord::getChainIndex).toList();
        assertThat(indices).hasSize(threads).doesNotHaveDuplicates();
        // Contiguous 1..8: no index skipped, none reused.
        assertThat(indices).containsExactlyElementsOf(
                java.util.stream.LongStream.rangeClosed(1, threads).boxed().toList());
        assertThat(auditService.verify(adminOfTenantA()).intact()).isTrue();
        assertThat(chainHeadRepository.findById("tenant-a").orElseThrow().getLastIndex()).isEqualTo(threads);
    }

    @Test
    @DisplayName("a failed append consumes no chain index and leaves no gap")
    void failedAppendConsumesNoIndex() throws Exception {
        auditService.append(ACTOR, request("first"), null);
        assertThat(chainHeadRepository.findById("tenant-a").orElseThrow().getLastIndex()).isEqualTo(1);

        // Force the insert to blow up after the chain head has been locked and the link
        // computed - the exact window where a non-transactional design would leak an index.
        Mockito.doThrow(new RuntimeException("simulated storage failure"))
                .when(recordRepository).saveAndFlush(Mockito.any(AuditRecord.class));

        assertThatThrownBy(() -> auditService.append(ACTOR, request("doomed"), null))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("simulated storage failure");

        Mockito.reset(recordRepository);

        // The head never advanced, so the next append takes index 2, not 3.
        assertThat(chainHeadRepository.findById("tenant-a").orElseThrow().getLastIndex()).isEqualTo(1);
        ApiModels.AuditEventResponse next = auditService.append(ACTOR, request("after-failure"), null).event();
        assertThat(next.chainIndex()).isEqualTo(2L);
        assertThat(recordRepository.findByTenantIdOrderByChainIndexAsc("tenant-a")).hasSize(2);
        assertThat(auditService.verify(adminOfTenantA()).intact()).isTrue();
    }

    @Test
    @DisplayName("a failed append does not burn its idempotency key")
    void failedAppendDoesNotBurnItsIdempotencyKey() throws Exception {
        Mockito.doThrow(new RuntimeException("simulated storage failure"))
                .when(recordRepository).saveAndFlush(Mockito.any(AuditRecord.class));

        assertThatThrownBy(() -> auditService.append(ACTOR, request("doomed"), "retry-key"))
                .isInstanceOf(RuntimeException.class);

        Mockito.reset(recordRepository);
        assertThat(idempotencyRepository.findByTenantIdAndIdempotencyKey("tenant-a", "retry-key")).isEmpty();

        // The client retries with the same key and gets a real append, not a phantom replay.
        ApiModels.AppendOutcome retried = auditService.append(ACTOR, request("doomed"), "retry-key");
        assertThat(retried.replayed()).isFalse();
        assertThat(retried.event().chainIndex()).isEqualTo(1L);
    }

    @Test
    @DisplayName("concurrent appends sharing one idempotency key create exactly one record")
    void concurrentAppendsWithTheSameKeyCreateOneRecord() throws Exception {
        int threads = 6;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger errors = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    go.await();
                    auditService.append(ACTOR, request("same"), "shared-retry-key");
                } catch (Exception exception) {
                    errors.incrementAndGet();
                }
            });
        }
        go.countDown();
        pool.shutdown();
        assertThat(pool.awaitTermination(30, TimeUnit.SECONDS)).isTrue();

        assertThat(errors.get()).isZero();
        assertThat(recordRepository.findByTenantIdOrderByChainIndexAsc("tenant-a")).hasSize(1);
        assertThat(auditService.verify(adminOfTenantA()).intact()).isTrue();
    }

    private static AuthenticatedActor adminOfTenantA() {
        return new AuthenticatedActor("admin", "admin-a", "tenant-a", true);
    }
}
