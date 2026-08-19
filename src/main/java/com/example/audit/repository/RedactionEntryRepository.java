package com.example.audit.repository;

import com.example.audit.domain.RedactionEntry;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RedactionEntryRepository extends JpaRepository<RedactionEntry, UUID> {
    List<RedactionEntry> findByRecordIdOrderBySequenceNumberAsc(UUID recordId);
    Optional<RedactionEntry> findTopByRecordIdOrderBySequenceNumberDesc(UUID recordId);
}
