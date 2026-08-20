package com.example.audit.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * Role-based access control for the audit API.
 *
 * <p>Three roles, matching the "high-impact action" boundary the exercise calls out:
 * <ul>
 *   <li>{@code ROLE_AUDIT_WRITER}  - append events only</li>
 *   <li>{@code ROLE_AUDIT_READER}  - query and verify (read-only)</li>
 *   <li>{@code ROLE_AUDIT_ADMIN}   - redact and export (privacy-impacting / evidentiary actions),
 *       plus read and write, since an admin must be able to see what they are redacting/exporting</li>
 * </ul>
 *
 * <p><b>Prototype boundary (see docs/RISKS_AND_TRADEOFFS.md):</b> users are in-memory and
 * credentials are dev-only defaults, overridable via environment variables. This is
 * appropriate for demonstrating role separation and endpoint-level enforcement, not for
 * production identity management. Production would replace this with an external IdP
 * (OAuth2/OIDC), short-lived tokens, and centrally managed secrets.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService(
            PasswordEncoder encoder,
            @Value("${audit.security.writer-password:writer-dev-pass}") String writerPassword,
            @Value("${audit.security.reader-password:reader-dev-pass}") String readerPassword,
            @Value("${audit.security.admin-password:admin-dev-pass}") String adminPassword) {

        UserDetails writer = User.withUsername("writer")
                .password(encoder.encode(writerPassword))
                .authorities("ROLE_AUDIT_WRITER")
                .build();

        UserDetails reader = User.withUsername("reader")
                .password(encoder.encode(readerPassword))
                .authorities("ROLE_AUDIT_READER")
                .build();

        UserDetails admin = User.withUsername("admin")
                .password(encoder.encode(adminPassword))
                .authorities("ROLE_AUDIT_WRITER", "ROLE_AUDIT_READER", "ROLE_AUDIT_ADMIN")
                .build();

        return new InMemoryUserDetailsManager(writer, reader, admin);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Stateless REST API authenticated per-request via HTTP Basic - no server-side
            // session/cookie is issued, so CSRF (a session/cookie-based attack) does not apply.
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                // API documentation is intentionally public for local/demo use.
                // Production: restrict or remove before exposing the service externally.
                .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()

                .requestMatchers(HttpMethod.POST, "/audit").hasAuthority("ROLE_AUDIT_WRITER")
                .requestMatchers(HttpMethod.POST, "/audit/*/redact").hasAuthority("ROLE_AUDIT_ADMIN")
                .requestMatchers(HttpMethod.GET, "/audit/export").hasAuthority("ROLE_AUDIT_ADMIN")
                .requestMatchers(HttpMethod.GET, "/audit/verify")
                        .hasAnyAuthority("ROLE_AUDIT_READER", "ROLE_AUDIT_ADMIN")
                .requestMatchers(HttpMethod.GET, "/audit")
                        .hasAnyAuthority("ROLE_AUDIT_READER", "ROLE_AUDIT_ADMIN")

                .anyRequest().authenticated()
            )
            .httpBasic(withDefaults());
        return http.build();
    }
}
