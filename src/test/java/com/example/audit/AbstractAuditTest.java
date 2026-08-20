package com.example.audit;

import com.example.audit.repository.AuditRecordRepository;
import com.example.audit.repository.ChainCheckpointRepository;
import com.example.audit.repository.ChainHeadRepository;
import com.example.audit.repository.IdempotencyRecordRepository;
import com.example.audit.repository.RedactionEntryRepository;
import com.example.audit.security.AuthenticatedActor;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Shared fixture for the HTTP-level suites.
 *
 * <p>State is reset by truncating the tables before each test rather than by rebuilding
 * the Spring context. Both give isolation, but a context rebuild per test method costs
 * seconds each and the suite is large enough that the difference is the difference
 * between a test suite people run and one they skip.
 *
 * <p>Two identity mechanisms are available, deliberately:
 * <ul>
 *   <li>Basic-auth users, bound to tenant-a in the test properties, for the ordinary
 *       role and ownership scenarios;</li>
 *   <li>JWT principals minted with arbitrary claims, for tenant-b. Cross-tenant
 *       scenarios need a second tenant to exist, and claims are how tenancy actually
 *       arrives in production - so those tests exercise the real mechanism instead of a
 *       test-only shortcut.</li>
 * </ul>
 */
@SpringBootTest
@AutoConfigureMockMvc
abstract class AbstractAuditTest {
    protected static final String TENANT_A = "tenant-a";
    protected static final String TENANT_B = "tenant-b";
    protected static final String ADVISOR_17 = "advisor-17";
    protected static final String ADVISOR_99 = "advisor-99";

    @Autowired protected MockMvc mvc;
    @Autowired protected ObjectMapper mapper;
    @Autowired protected AuditRecordRepository recordRepository;
    @Autowired protected RedactionEntryRepository redactionRepository;
    @Autowired protected ChainHeadRepository chainHeadRepository;
    @Autowired protected ChainCheckpointRepository checkpointRepository;
    @Autowired protected IdempotencyRecordRepository idempotencyRepository;

    @BeforeEach
    void resetAuditState() {
        redactionRepository.deleteAll();
        checkpointRepository.deleteAll();
        idempotencyRepository.deleteAll();
        recordRepository.deleteAll();
        chainHeadRepository.deleteAll();
    }

    protected static RequestPostProcessor asWriter() {
        return SecurityMockMvcRequestPostProcessors.httpBasic("writer", "test-writer-password");
    }

    protected static RequestPostProcessor asReader() {
        return SecurityMockMvcRequestPostProcessors.httpBasic("reader", "test-reader-password");
    }

    protected static RequestPostProcessor asAdmin() {
        return SecurityMockMvcRequestPostProcessors.httpBasic("admin", "test-admin-password");
    }

    /** A JWT principal with explicit actor/tenant claims and the given roles. */
    protected static RequestPostProcessor asToken(String actorId, String tenantId, String... roles) {
        SimpleGrantedAuthority[] authorities = new SimpleGrantedAuthority[roles.length];
        for (int i = 0; i < roles.length; i++) {
            authorities[i] = new SimpleGrantedAuthority(roles[i]);
        }
        return SecurityMockMvcRequestPostProcessors.jwt()
                .jwt(builder -> builder.subject(actorId).claim("tenant_id", tenantId))
                .authorities(authorities);
    }

    protected static AuthenticatedActor actor(String actorId, String tenantId, boolean admin) {
        return new AuthenticatedActor(actorId, actorId, tenantId, admin);
    }

    protected static String eventBody(String eventType, String resourceId) {
        return "{\"eventType\":\"" + eventType + "\",\"resourceType\":\"ACCOUNT\",\"resourceId\":\""
                + resourceId + "\",\"payload\":{\"ok\":true}}";
    }
}
