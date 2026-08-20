package com.example.audit.security;

import com.example.audit.config.AuditProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Minimal fixed-window rate limiter, keyed by authenticated principal (falls back to
 * remote address for unauthenticated requests, e.g. repeated failed logins). In-memory
 * only - resets on restart and does not share state across nodes; adequate to
 * demonstrate abuse protection for a single-node prototype, NOT a production rate
 * limiter (see docs/RISKS_AND_TRADEOFFS.md for the production alternative: a shared
 * store such as Redis, or an API gateway / ingress-level limiter).
 *
 * <p><b>Not a {@code @Component}/auto-registered filter on purpose:</b> it must run
 * AFTER Spring Security's authentication filter so {@code SecurityContextHolder} is
 * already populated when it reads the principal - see
 * {@code SecurityConfig#filterChain}, which wires it in explicitly via
 * {@code addFilterAfter(..., BasicAuthenticationFilter.class)}. Letting Spring Boot
 * auto-register this as a generic servlet filter would run it too early, before
 * authentication, and it would silently fall back to IP-only limiting for every
 * request regardless of who is logged in.
 */
public class RateLimitFilter extends OncePerRequestFilter {
    private final AuditProperties properties;
    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    public RateLimitFilter(AuditProperties properties) {
        this.properties = properties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (!properties.getRateLimit().isEnabled()) {
            chain.doFilter(request, response);
            return;
        }
        String key = principalKey(request);
        long nowMinute = Instant.now().getEpochSecond() / 60;
        Window window = windows.computeIfAbsent(key, ignored -> new Window(nowMinute));

        synchronized (window) {
            if (window.minute != nowMinute) {
                window.minute = nowMinute;
                window.count.set(0);
            }
            if (window.count.incrementAndGet() > properties.getRateLimit().getRequestsPerMinute()) {
                response.setStatus(429);
                response.setContentType("application/problem+json");
                response.getWriter().write("{\"title\":\"Too Many Requests\",\"status\":429,"
                        + "\"detail\":\"Rate limit of " + properties.getRateLimit().getRequestsPerMinute()
                        + " requests/minute exceeded for this principal\"}");
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private String principalKey(HttpServletRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()
                && !"anonymousUser".equals(authentication.getPrincipal())) {
            return "user:" + authentication.getName();
        }
        return "ip:" + request.getRemoteAddr();
    }

    private static final class Window {
        private volatile long minute;
        private final AtomicInteger count = new AtomicInteger();
        private Window(long minute) { this.minute = minute; }
    }
}
