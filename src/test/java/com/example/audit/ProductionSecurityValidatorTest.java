package com.example.audit;

import com.example.audit.config.AuditProperties;
import com.example.audit.config.ProductionSecurityValidator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The fail-closed production gate.
 *
 * <p>Absent placeholders alone do not make a configuration safe - an empty environment
 * variable satisfies a placeholder, and several dangerous states (Basic auth left
 * enabled, ephemeral keys, no TLS anywhere, automatic schema updates) are not
 * placeholder-shaped at all. These tests pin each rule individually, so a future change
 * that quietly relaxes one is a failing test rather than a deployment that starts
 * anyway.
 */
class ProductionSecurityValidatorTest {

    /** A configuration that satisfies every rule; each test then breaks exactly one. */
    private static AuditProperties secureProperties() {
        AuditProperties properties = new AuditProperties();
        properties.getSecurity().getOidc().setEnabled(true);
        properties.getSecurity().getOidc().setIssuerUri("https://idp.example.com/");
        properties.getSecurity().getBasic().setEnabled(false);
        properties.getSigning().setKeyId("kms-key-1");
        properties.getSigning().setPrivateKeyBase64("private-material");
        properties.getSigning().setPublicKeyBase64("public-material");
        properties.getSigning().setAllowEphemeral(false);
        properties.getSecurity().getTls().setExternallyTerminated(true);
        return properties;
    }

    private static MockEnvironment secureEnvironment() {
        return new MockEnvironment()
                .withProperty("springdoc.api-docs.enabled", "false")
                .withProperty("springdoc.swagger-ui.enabled", "false")
                .withProperty("spring.h2.console.enabled", "false")
                .withProperty("spring.jpa.hibernate.ddl-auto", "validate")
                .withProperty("spring.datasource.url", "jdbc:postgresql://db:5432/audit");
    }

    private static List<String> problemsFor(AuditProperties properties, MockEnvironment environment) {
        return new ProductionSecurityValidator(properties, environment).validate();
    }

    @Test
    @DisplayName("a fully configured production setup starts")
    void secureConfigurationPasses() {
        assertThat(problemsFor(secureProperties(), secureEnvironment())).isEmpty();
        assertThatCode(() -> new ProductionSecurityValidator(secureProperties(), secureEnvironment())
                .afterPropertiesSet()).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("startup aborts, listing every problem at once")
    void insecureConfigurationAbortsStartupWithAllProblems() {
        AuditProperties properties = new AuditProperties();

        assertThatThrownBy(() -> new ProductionSecurityValidator(properties, new MockEnvironment())
                .afterPropertiesSet())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Refusing to start")
                .hasMessageContaining("audit.security.oidc.enabled")
                .hasMessageContaining("audit.security.basic.enabled")
                .hasMessageContaining("signing key source")
                .hasMessageContaining("TLS is not configured");
    }

    @Test
    @DisplayName("OIDC is mandatory in production")
    void oidcIsMandatory() {
        AuditProperties properties = secureProperties();
        properties.getSecurity().getOidc().setEnabled(false);

        assertThat(problemsFor(properties, secureEnvironment()))
                .anyMatch(problem -> problem.contains("audit.security.oidc.enabled must be true"));
    }

    @Test
    @DisplayName("OIDC without an issuer or JWK set URI is rejected")
    void oidcNeedsAnIssuerOrJwkSetUri() {
        AuditProperties properties = secureProperties();
        properties.getSecurity().getOidc().setIssuerUri("");

        assertThat(problemsFor(properties, secureEnvironment()))
                .anyMatch(problem -> problem.contains("issuer-uri"));
    }

    @Test
    @DisplayName("in-memory Basic auth is rejected in production")
    void basicAuthIsRejected() {
        AuditProperties properties = secureProperties();
        properties.getSecurity().getBasic().setEnabled(true);

        assertThat(problemsFor(properties, secureEnvironment()))
                .anyMatch(problem -> problem.contains("audit.security.basic.enabled must be false"));
    }

    @Test
    @DisplayName("ephemeral signing keys are rejected in production")
    void ephemeralSigningKeysAreRejected() {
        AuditProperties properties = secureProperties();
        properties.getSigning().setAllowEphemeral(true);

        assertThat(problemsFor(properties, secureEnvironment()))
                .anyMatch(problem -> problem.contains("allow-ephemeral must be false"));
    }

    @Test
    @DisplayName("no durable key source is rejected")
    void missingKeySourceIsRejected() {
        AuditProperties properties = secureProperties();
        properties.getSigning().setPrivateKeyBase64("");
        properties.getSigning().setPublicKeyBase64("");

        assertThat(problemsFor(properties, secureEnvironment()))
                .anyMatch(problem -> problem.contains("durable signing key source"));
    }

    @Test
    @DisplayName("configured keys without a key id are rejected, since signatures must name their key")
    void configuredKeysNeedAKeyId() {
        AuditProperties properties = secureProperties();
        properties.getSigning().setKeyId("");

        assertThat(problemsFor(properties, secureEnvironment()))
                .anyMatch(problem -> problem.contains("key-id"));
    }

    @Test
    @DisplayName("TLS must be terminated here or explicitly declared as terminated upstream")
    void tlsMustBeAccountedFor() {
        AuditProperties properties = secureProperties();
        properties.getSecurity().getTls().setExternallyTerminated(false);

        assertThat(problemsFor(properties, secureEnvironment()))
                .anyMatch(problem -> problem.contains("TLS is not configured"));

        // Terminating TLS in the application itself also satisfies the rule.
        assertThat(problemsFor(properties, secureEnvironment().withProperty("server.ssl.enabled", "true")))
                .noneMatch(problem -> problem.contains("TLS is not configured"));
    }

    @Test
    @DisplayName("wildcard CORS is rejected")
    void wildcardCorsIsRejected() {
        AuditProperties properties = secureProperties();
        properties.getSecurity().getCors().setAllowedOrigins(List.of("*"));

        assertThat(problemsFor(properties, secureEnvironment()))
                .anyMatch(problem -> problem.contains("must not contain '*'"));
    }

    @Test
    @DisplayName("H2 console, Swagger and API docs must all be off")
    void debugSurfacesMustBeOff() {
        assertThat(problemsFor(secureProperties(),
                secureEnvironment().withProperty("spring.h2.console.enabled", "true")))
                .anyMatch(problem -> problem.contains("h2.console"));
        assertThat(problemsFor(secureProperties(),
                secureEnvironment().withProperty("springdoc.api-docs.enabled", "true")))
                .anyMatch(problem -> problem.contains("api-docs"));
        assertThat(problemsFor(secureProperties(),
                secureEnvironment().withProperty("springdoc.swagger-ui.enabled", "true")))
                .anyMatch(problem -> problem.contains("swagger-ui"));
    }

    @Test
    @DisplayName("an H2 datasource is rejected in production")
    void h2DatasourceIsRejected() {
        assertThat(problemsFor(secureProperties(),
                secureEnvironment().withProperty("spring.datasource.url", "jdbc:h2:file:./data/auditdb")))
                .anyMatch(problem -> problem.contains("H2"));
    }

    @Test
    @DisplayName("automatic schema updates are rejected for an append-only store")
    void automaticSchemaUpdatesAreRejected() {
        assertThat(problemsFor(secureProperties(),
                secureEnvironment().withProperty("spring.jpa.hibernate.ddl-auto", "update")))
                .anyMatch(problem -> problem.contains("ddl-auto"));
    }
}
