package com.example.audit.config;

import com.example.audit.security.RateLimitFilter;
import com.example.audit.security.RequestSizeLimitFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * Authentication and the coarse role gate.
 *
 * <p><b>Authentication model.</b> OIDC/OAuth2 bearer tokens are the intended mechanism
 * and the only one the production profile permits: set
 * {@code audit.security.oidc.enabled=true} with an issuer or JWK set URI and the service
 * becomes a resource server, delegating credential handling, session lifetime and MFA to
 * the identity provider where they belong. HTTP Basic survives only as a local
 * development and test fallback, and {@link ProductionSecurityValidator} rejects it in
 * production.
 *
 * <p><b>No credentials in the repository.</b> The Basic users have no default passwords.
 * If one is not supplied through configuration, a random password is generated at startup
 * and logged, the way Spring Boot handles its own default user - developers get a working
 * login, and there is no fixed secret to leak or to accidentally ship.
 *
 * <p><b>Roles here, ownership in the service layer.</b> The matchers below decide which
 * roles may reach which endpoint. They deliberately do not decide whose data may be
 * touched: that depends on the record, so it lives with the record - see
 * {@code AuditAccessPolicy}. A route that is somehow reachable without passing a matcher
 * still cannot cross a tenant boundary.
 *
 * <p><b>CSRF.</b> Disabled, as an explicit decision about the deployment model rather
 * than a default left in place. The API is stateless, authenticated per request by a
 * bearer token or Basic header, and issues no session cookie, so there is no
 * ambient credential for a cross-site request to ride on. The property
 * {@code audit.security.csrf-enabled} exists to turn protection back on the moment this
 * service is fronted by a cookie/session browser flow, which is the condition that would
 * make CSRF applicable.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService(PasswordEncoder encoder, AuditProperties properties) {
        AuditProperties.Basic basic = properties.getSecurity().getBasic();
        UserDetails writer = User.withUsername("writer")
                .password(encoder.encode(resolvePassword(basic.getWriterPassword(), "writer")))
                .authorities("ROLE_AUDIT_WRITER")
                .build();
        UserDetails reader = User.withUsername("reader")
                .password(encoder.encode(resolvePassword(basic.getReaderPassword(), "reader")))
                .authorities("ROLE_AUDIT_READER")
                .build();
        UserDetails admin = User.withUsername("admin")
                .password(encoder.encode(resolvePassword(basic.getAdminPassword(), "admin")))
                .authorities("ROLE_AUDIT_WRITER", "ROLE_AUDIT_READER", "ROLE_AUDIT_ADMIN")
                .build();
        return new InMemoryUserDetailsManager(writer, reader, admin);
    }

    /**
     * Returns the configured password, or mints a random one and logs it. Never returns
     * a compiled-in constant - a shipped default password is a credential in the
     * repository no matter how it is labelled.
     */
    private static String resolvePassword(String configured, String username) {
        if (configured != null && !configured.isBlank()) {
            return configured;
        }
        String generated = UUID.randomUUID().toString();
        LOGGER.warn("""

                =====================================================================
                No password configured for local Basic-auth user '{}'.
                Generated for this run only: {}
                Set audit.security.basic.{}-password (or the matching environment
                variable) to pin it. Basic auth is for local development and tests;
                production must use OIDC - the prod profile refuses to start without it.
                =====================================================================""",
                username, generated, username);
        return generated;
    }

    @Bean
    public RateLimitFilter rateLimitFilter(AuditProperties properties) {
        return new RateLimitFilter(properties);
    }

    @Bean
    public RequestSizeLimitFilter requestSizeLimitFilter(AuditProperties properties) {
        return new RequestSizeLimitFilter(properties);
    }

    /**
     * Deny-by-default CORS. With no configured origins the configuration carries no
     * allowed origin at all, so every cross-origin browser call is refused. Wildcards
     * are never applied, and credentials are never allowed.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource(AuditProperties properties) {
        List<String> allowedOrigins = properties.getSecurity().getCors().getAllowedOrigins().stream()
                .filter(origin -> origin != null && !origin.isBlank())
                .toList();
        CorsConfiguration configuration = new CorsConfiguration();
        if (!allowedOrigins.isEmpty()) {
            configuration.setAllowedOrigins(allowedOrigins);
            configuration.setAllowedMethods(List.of("GET", "POST"));
            configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "Idempotency-Key"));
            configuration.setAllowCredentials(false);
            configuration.setMaxAge(600L);
        }
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * Maps token claims onto the service roles. Reads the configured roles claim and
     * also honours standard OAuth2 scopes, so either token shape works without the
     * application inventing authorities the IdP did not grant.
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter(AuditProperties properties) {
        String rolesClaim = properties.getIdentity().getRolesClaim();
        JwtGrantedAuthoritiesConverter scopes = new JwtGrantedAuthoritiesConverter();
        Converter<Jwt, Collection<GrantedAuthority>> converter = jwt -> {
            Collection<GrantedAuthority> authorities = new ArrayList<>(scopes.convert(jwt));
            Object claim = jwt.getClaim(rolesClaim);
            if (claim instanceof Collection<?> roles) {
                for (Object role : roles) {
                    String value = String.valueOf(role);
                    authorities.add(new SimpleGrantedAuthority(
                            value.startsWith("ROLE_") ? value : "ROLE_" + value));
                }
            }
            return authorities;
        };
        JwtAuthenticationConverter authenticationConverter = new JwtAuthenticationConverter();
        authenticationConverter.setJwtGrantedAuthoritiesConverter(converter);
        return authenticationConverter;
    }

    /**
     * Builds the token decoder from {@code audit.security.oidc.*} so there is one place
     * that describes the IdP, rather than requiring the same issuer to be repeated under
     * {@code spring.security.oauth2.*} and kept in sync.
     *
     * <p>A JWK set URI is resolved lazily; an issuer URI is resolved at startup via
     * discovery, which also validates that the configured issuer is reachable and real.
     * Audience is checked when configured, so a token minted for a different service
     * cannot be replayed against this one.
     */
    @Bean
    @ConditionalOnProperty(name = "audit.security.oidc.enabled", havingValue = "true")
    public JwtDecoder jwtDecoder(AuditProperties properties) {
        AuditProperties.Oidc oidc = properties.getSecurity().getOidc();
        NimbusJwtDecoder decoder = oidc.getJwkSetUri().isBlank()
                ? (NimbusJwtDecoder) JwtDecoders.fromIssuerLocation(oidc.getIssuerUri())
                : NimbusJwtDecoder.withJwkSetUri(oidc.getJwkSetUri()).build();

        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new JwtTimestampValidator());
        if (!oidc.getIssuerUri().isBlank()) {
            validators.add(new JwtIssuerValidator(oidc.getIssuerUri()));
        }
        if (!oidc.getAudience().isBlank()) {
            validators.add(new JwtClaimValidator<List<String>>("aud",
                    audiences -> audiences != null && audiences.contains(oidc.getAudience())));
        }
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(validators));
        return decoder;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuditProperties properties,
                                           RateLimitFilter rateLimitFilter,
                                           RequestSizeLimitFilter requestSizeLimitFilter,
                                           CorsConfigurationSource corsConfigurationSource,
                                           JwtAuthenticationConverter jwtAuthenticationConverter) throws Exception {
        boolean oidc = properties.getSecurity().getOidc().isEnabled();
        boolean apiDocsPublic = !oidc && properties.getSecurity().getBasic().isEnabled();

        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            .csrf(csrf -> {
                if (!properties.getSecurity().isCsrfEnabled()) {
                    csrf.disable();
                }
            })
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> {
                if (apiDocsPublic) {
                    // Local/dev convenience only. Switched off wholesale in production,
                    // where springdoc itself is disabled and this branch is not taken.
                    auth.requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll();
                }
                auth
                    .requestMatchers(HttpMethod.POST, "/audit").hasAuthority("ROLE_AUDIT_WRITER")
                    .requestMatchers(HttpMethod.POST, "/audit/*/redact").hasAuthority("ROLE_AUDIT_ADMIN")
                    .requestMatchers(HttpMethod.POST, "/audit/retention/run").hasAuthority("ROLE_AUDIT_ADMIN")
                    .requestMatchers(HttpMethod.POST, "/audit/archive").hasAuthority("ROLE_AUDIT_ADMIN")
                    .requestMatchers(HttpMethod.POST, "/audit/checkpoints").hasAuthority("ROLE_AUDIT_ADMIN")
                    .requestMatchers(HttpMethod.GET, "/audit/checkpoints").hasAuthority("ROLE_AUDIT_ADMIN")
                    .requestMatchers(HttpMethod.GET, "/audit/export").hasAuthority("ROLE_AUDIT_ADMIN")
                    .requestMatchers(HttpMethod.GET, "/audit/verify")
                            .hasAnyAuthority("ROLE_AUDIT_READER", "ROLE_AUDIT_ADMIN")
                    .requestMatchers(HttpMethod.GET, "/audit", "/audit/*")
                            .hasAnyAuthority("ROLE_AUDIT_READER", "ROLE_AUDIT_ADMIN")
                    .anyRequest().authenticated();
            })
            .addFilterBefore(requestSizeLimitFilter, BasicAuthenticationFilter.class);

        if (oidc) {
            http.oauth2ResourceServer(server -> server.jwt(jwt -> jwt.jwtAuthenticationConverter(
                    (Converter<Jwt, AbstractAuthenticationToken>) jwtAuthenticationConverter)));
        } else {
            http.httpBasic(basic -> { });
        }
        // After authentication, so the limiter keys on the principal rather than only on IP.
        http.addFilterAfter(rateLimitFilter, BasicAuthenticationFilter.class);
        return http.build();
    }
}
