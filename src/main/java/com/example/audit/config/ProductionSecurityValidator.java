package com.example.audit.config;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Refuses to start a production instance that is not actually secured.
 *
 * <p>Relying on "no default value in the properties file" alone is not enough: a
 * placeholder can be satisfied by an empty environment variable, and several of the
 * required conditions (Basic auth left on, ephemeral signing keys, TLS neither
 * terminated here nor acknowledged as terminated upstream) are not expressible as a
 * missing placeholder at all. This runs every such check explicitly and reports all
 * failures at once, so an operator fixes the whole set in one pass rather than
 * discovering them one restart at a time.
 *
 * <p>Only active under the {@code prod} profile, which is what keeps development and
 * test runs usable while leaving production fail-closed.
 */
@Component
@Profile("prod")
public class ProductionSecurityValidator implements InitializingBean {
    private final AuditProperties properties;
    private final Environment environment;

    public ProductionSecurityValidator(AuditProperties properties, Environment environment) {
        this.properties = properties;
        this.environment = environment;
    }

    @Override
    public void afterPropertiesSet() {
        List<String> problems = validate();
        if (!problems.isEmpty()) {
            throw new IllegalStateException("Refusing to start with an insecure production configuration:"
                    + System.lineSeparator() + "  - " + String.join(System.lineSeparator() + "  - ", problems));
        }
    }

    /** Exposed so the rules can be asserted directly - see {@code ProductionSecurityValidatorTest}. */
    public List<String> validate() {
        List<String> problems = new ArrayList<>();
        AuditProperties.Security security = properties.getSecurity();

        if (!security.getOidc().isEnabled()) {
            problems.add("audit.security.oidc.enabled must be true in production - external IdP "
                    + "authentication (and MFA, which belongs to the IdP) is required");
        } else if (security.getOidc().getIssuerUri().isBlank() && security.getOidc().getJwkSetUri().isBlank()) {
            problems.add("audit.security.oidc.issuer-uri or audit.security.oidc.jwk-set-uri must be set");
        }

        if (security.getBasic().isEnabled()) {
            problems.add("audit.security.basic.enabled must be false in production - HTTP Basic with "
                    + "in-memory users is a development mechanism only");
        }

        AuditProperties.Signing signing = properties.getSigning();
        boolean configuredKeys = !signing.getPrivateKeyBase64().isBlank()
                && !signing.getPublicKeyBase64().isBlank();
        if (signing.isAllowEphemeral()) {
            problems.add("audit.signing.allow-ephemeral must be false in production - an ephemeral key "
                    + "makes every signature issued before a restart permanently unverifiable");
        }
        if (!configuredKeys && signing.getStorePath().isBlank()) {
            problems.add("A durable signing key source is required: set audit.signing.private-key-base64 "
                    + "and audit.signing.public-key-base64 from a KMS/secret store, or audit.signing.store-path");
        }
        if (configuredKeys && signing.getKeyId().isBlank()) {
            problems.add("audit.signing.key-id must be set so signatures name the key that produced them");
        }

        if (!environment.getProperty("server.ssl.enabled", Boolean.class, false)
                && !security.getTls().isExternallyTerminated()) {
            problems.add("TLS is not configured: set server.ssl.enabled=true with a keystore, or set "
                    + "audit.security.tls.externally-terminated=true to record that a proxy/ingress "
                    + "terminates TLS in front of this service");
        }

        if (security.getCors().getAllowedOrigins().stream().anyMatch("*"::equals)) {
            problems.add("audit.security.cors.allowed-origins must not contain '*'");
        }

        if (environment.getProperty("spring.h2.console.enabled", Boolean.class, false)) {
            problems.add("spring.h2.console.enabled must be false in production");
        }
        if (environment.getProperty("springdoc.api-docs.enabled", Boolean.class, true)) {
            problems.add("springdoc.api-docs.enabled must be false in production");
        }
        if (environment.getProperty("springdoc.swagger-ui.enabled", Boolean.class, true)) {
            problems.add("springdoc.swagger-ui.enabled must be false in production");
        }

        String ddlAuto = environment.getProperty("spring.jpa.hibernate.ddl-auto", "none");
        if (!"none".equals(ddlAuto) && !"validate".equals(ddlAuto)) {
            problems.add("spring.jpa.hibernate.ddl-auto must be 'none' or 'validate' in production, not '"
                    + ddlAuto + "' - schema changes to an append-only audit store belong in reviewed "
                    + "migrations, not in an automatic update");
        }

        String datasourceUrl = environment.getProperty("spring.datasource.url", "");
        if (datasourceUrl.startsWith("jdbc:h2:")) {
            problems.add("spring.datasource.url points at H2; production must use a real, "
                    + "access-controlled database");
        }
        return problems;
    }
}
