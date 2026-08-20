package com.example.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Rate limiting, with its own low ceiling so the limiter can actually be tripped without
 * an unrealistic number of requests and without changing the ceiling every other test
 * runs under.
 *
 * <p>The context is rebuilt between methods because the limiter holds a fixed-window
 * counter per principal in memory. Without that, whichever test ran first would spend
 * the budget and the next would see a 429 on its first request - a passing test turning
 * into a confusing failure purely through ordering.
 */
@SpringBootTest(properties = "audit.rate-limit.requests-per-minute=3")
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
class RateLimitFilterTest {

    @Autowired MockMvc mvc;

    private static org.springframework.test.web.servlet.request.RequestPostProcessor reader() {
        return SecurityMockMvcRequestPostProcessors.httpBasic("reader", "test-reader-password");
    }

    private static org.springframework.test.web.servlet.request.RequestPostProcessor admin() {
        return SecurityMockMvcRequestPostProcessors.httpBasic("admin", "test-admin-password");
    }

    @Test
    @DisplayName("requests beyond the ceiling are refused with 429 and a problem body")
    void requestsBeyondTheCeilingAreRejected() throws Exception {
        for (int i = 0; i < 3; i++) {
            mvc.perform(get("/audit/verify").with(reader())).andExpect(status().isOk());
        }

        mvc.perform(get("/audit/verify").with(reader()))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.status").value(429))
                .andExpect(jsonPath("$.title").value("Too Many Requests"));
    }

    @Test
    @DisplayName("one principal exhausting its budget does not affect another")
    void limitsArePerPrincipal() throws Exception {
        for (int i = 0; i < 3; i++) {
            mvc.perform(get("/audit/verify").with(reader())).andExpect(status().isOk());
        }

        mvc.perform(get("/audit/verify").with(admin())).andExpect(status().isOk());
    }

    @Test
    @DisplayName("unauthenticated requests are still refused, so the limiter is not an auth bypass")
    void unauthenticatedRequestsAreStillRejected() throws Exception {
        mvc.perform(get("/audit/verify")).andExpect(status().isUnauthorized());
    }
}
