package com.example.audit.repository;

import com.example.audit.domain.IdempotencyRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface IdempotencyRecordRepository extends JpaRepository<IdempotencyRecord, UUID> {
    Optional<IdempotencyRecord> findByTenantIdAndIdempotencyKey(String tenantId, String idempotencyKey);
    List<IdempotencyRecord> findByCreatedAtBefore(Instant cutoff);
}
