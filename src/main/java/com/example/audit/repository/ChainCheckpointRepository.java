package com.example.audit.repository;

import com.example.audit.domain.ChainCheckpoint;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ChainCheckpointRepository extends JpaRepository<ChainCheckpoint, UUID> {
    List<ChainCheckpoint> findByTenantIdOrderByChainIndexAsc(String tenantId);
    Optional<ChainCheckpoint> findTopByTenantIdOrderByChainIndexDesc(String tenantId);
}
