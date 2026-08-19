package com.example.audit.service;

import com.example.audit.config.AuditProperties;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Service
public class RetentionService {
    private final AuditService auditService;
    private final AuditProperties properties;

    public RetentionService(AuditService auditService, AuditProperties properties) {
        this.auditService = auditService;
        this.properties = properties;
    }

    @Scheduled(cron = "${audit.retention.cron:0 0 2 * * *}")
    public void applyRetentionPolicy() {
        if (properties.getRetention().isEnabled()) {
            auditService.archiveOlderThan(Instant.now().minus(properties.getRetention().getDays(), ChronoUnit.DAYS));
        }
    }
}
