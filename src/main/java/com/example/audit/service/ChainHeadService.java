package com.example.audit.service;

import com.example.audit.domain.ChainHead;
import com.example.audit.repository.ChainHeadRepository;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Creates the per-tenant chain head row that appends later lock against.
 *
 * <p>There is nothing to take a row lock on until the row exists, so it has to be
 * committed before the first append can serialize against it - which is precisely the
 * race the old "read the last record" approach could not close on an empty table.
 *
 * <p>Note the split between {@link #ensureExists} and {@link Creator#create}. The insert
 * runs in its own transaction; the duplicate-key failure is caught <em>outside</em> that
 * transaction. Catching it inside would leave the transaction marked rollback-only and
 * turn a successfully-handled race into an {@code UnexpectedRollbackException} at commit
 * - which is exactly what happened when this was written as a single method, and is why
 * the concurrency test failed seven times out of eight before the split.
 */
@Service
public class ChainHeadService {
    private final ChainHeadRepository chainHeads;
    private final Creator creator;

    public ChainHeadService(ChainHeadRepository chainHeads, Creator creator) {
        this.chainHeads = chainHeads;
        this.creator = creator;
    }

    public void ensureExists(String tenantId) {
        if (chainHeads.existsById(tenantId)) {
            return;
        }
        try {
            creator.create(tenantId);
        } catch (DataAccessException concurrentCreate) {
            // Another node or thread created it first. The row existing is the only
            // outcome this method cares about, so a lost race is a success.
            if (!chainHeads.existsById(tenantId)) {
                throw concurrentCreate;
            }
        }
    }

    /** Separate bean so the transactional proxy applies and commits before the caller resumes. */
    @Service
    public static class Creator {
        private final ChainHeadRepository chainHeads;

        public Creator(ChainHeadRepository chainHeads) {
            this.chainHeads = chainHeads;
        }

        @Transactional(propagation = Propagation.REQUIRES_NEW)
        public void create(String tenantId) {
            chainHeads.saveAndFlush(new ChainHead(tenantId, 0L, AuditService.GENESIS_HASH));
        }
    }
}
