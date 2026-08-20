package com.example.audit.repository;

import com.example.audit.domain.ChainHead;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface ChainHeadRepository extends JpaRepository<ChainHead, String> {

    /**
     * Takes a database-level write lock on the tenant chain head. Because the lock lives
     * in the shared database and is held for the duration of the append transaction, it
     * serializes writers across every node in a cluster - unlike the in-process
     * {@code synchronized} it replaces.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select h from ChainHead h where h.tenantId = :tenantId")
    Optional<ChainHead> lockByTenantId(@Param("tenantId") String tenantId);
}
