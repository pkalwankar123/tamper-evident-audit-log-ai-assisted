package com.example.audit.security;

import com.example.audit.config.AuditProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Rejects oversized requests on the declared {@code Content-Length}, before the body is
 * read or parsed.
 *
 * <p>The service-layer size check remains as the authoritative limit, but it only fires
 * after Jackson has already materialised the whole payload - so on its own it lets an
 * attacker force the server to buffer and parse arbitrarily large JSON before being
 * told no. Checking the declared length first turns that into a cheap rejection.
 * Requests that omit or understate {@code Content-Length} still hit the service check,
 * and the container caps what it will swallow, so this is a fast path rather than the
 * only line of defence.
 */
public class RequestSizeLimitFilter extends OncePerRequestFilter {
    private final AuditProperties properties;

    public RequestSizeLimitFilter(AuditProperties properties) {
        this.properties = properties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        long declaredLength = request.getContentLengthLong();
        int limit = properties.getPayload().getMaxBytes();
        if (declaredLength > limit) {
            response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
            response.setContentType("application/problem+json");
            response.getWriter().write("{\"title\":\"Payload too large\",\"status\":413,"
                    + "\"detail\":\"Request body of " + declaredLength + " bytes exceeds the " + limit
                    + " byte limit\"}");
            return;
        }
        chain.doFilter(request, response);
    }
}
