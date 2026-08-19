package com.example.audit.repository;

import com.example.audit.domain.AuditRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;

import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AuditRecordRepository extends JpaRepository<AuditRecord, UUID>, JpaSpecificationExecutor<AuditRecord> {
    Optional<AuditRecord> findTopByOrderByChainIndexDesc();
    List<AuditRecord> findAllByOrderByChainIndexAsc();
    List<AuditRecord> findByTimestampBeforeAndArchivedFalse(Instant cutoff);
    List<AuditRecord> findByChainIndexBetweenOrderByChainIndexAsc(long from, long to);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select a from AuditRecord a where a.chainIndex = (select max(b.chainIndex) from AuditRecord b)")
    Optional<AuditRecord> lockTail();
}
