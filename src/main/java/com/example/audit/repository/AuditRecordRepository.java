package com.example.audit.repository;

import com.example.audit.domain.AuditRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface AuditRecordRepository extends JpaRepository<AuditRecord, UUID>, JpaSpecificationExecutor<AuditRecord> {

    List<AuditRecord> findByTenantIdOrderByChainIndexAsc(String tenantId);

    List<AuditRecord> findByTenantIdAndTimestampBeforeAndArchivedFalse(String tenantId, Instant cutoff);

    long countByTenantId(String tenantId);
}
