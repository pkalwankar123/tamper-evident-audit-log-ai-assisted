package com.example.audit.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Typed configuration for every security-relevant knob in the service.
 *
 * <p>Nothing in this class carries a credential-shaped default. Passwords, signing keys
 * and issuer URIs all default to blank so that a missing value is an explicit,
 * detectable absence rather than a silently-applied demo secret. The {@code prod}
 * profile is validated at startup by {@code ProductionSecurityValidator}, which refuses
 * to let the context finish building while any required value is still blank.
 */
@Configuration
@ConfigurationProperties(prefix = "audit")
public class AuditProperties {
    private final Retention retention = new Retention();
    private final Signing signing = new Signing();
    private final Identity identity = new Identity();
    private final Payload payload = new Payload();
    private final RateLimit rateLimit = new RateLimit();
    private final Security security = new Security();
    private final Idempotency idempotency = new Idempotency();

    public Retention getRetention() { return retention; }
    public Signing getSigning() { return signing; }
    public Identity getIdentity() { return identity; }
    public Payload getPayload() { return payload; }
    public RateLimit getRateLimit() { return rateLimit; }
    public Security getSecurity() { return security; }
    public Idempotency getIdempotency() { return idempotency; }

    public static class Retention {
        private boolean enabled;
        private int days = 365;
        private String cron = "0 0 2 * * *";
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getDays() { return days; }
        public void setDays(int days) { this.days = days; }
        public String getCron() { return cron; }
        public void setCron(String cron) { this.cron = cron; }
    }

    /**
     * Signing key material configuration.
     *
     * <p>{@code allowEphemeral} defaults to {@code false}: when no key source is
     * configured the application fails to start rather than silently minting a
     * throwaway keypair that would make every previously exported bundle unverifiable
     * after a restart. Local development opts in explicitly, or points
     * {@code storePath} at a durable file.
     */
    public static class Signing {
        private String keyId = "";
        private String privateKeyBase64 = "";
        private String publicKeyBase64 = "";
        private String storePath = "";
        private boolean allowEphemeral;
        public String getKeyId() { return keyId; }
        public void setKeyId(String keyId) { this.keyId = keyId; }
        public String getPrivateKeyBase64() { return privateKeyBase64; }
        public void setPrivateKeyBase64(String privateKeyBase64) { this.privateKeyBase64 = privateKeyBase64; }
        public String getPublicKeyBase64() { return publicKeyBase64; }
        public void setPublicKeyBase64(String publicKeyBase64) { this.publicKeyBase64 = publicKeyBase64; }
        public String getStorePath() { return storePath; }
        public void setStorePath(String storePath) { this.storePath = storePath; }
        public boolean isAllowEphemeral() { return allowEphemeral; }
        public void setAllowEphemeral(boolean allowEphemeral) { this.allowEphemeral = allowEphemeral; }
    }

    /**
     * How an authenticated principal is mapped onto the (actorId, tenantId) pair used
     * for every authorization decision. Callers never supply either value.
     *
     * <p>With OIDC/JWT the values come from token claims. With the local HTTP Basic
     * fallback they come from {@code audit.identity.principals.<username>.*}. A
     * principal with no resolvable binding is denied outright.
     */
    public static class Identity {
        private String actorClaim = "sub";
        private String tenantClaim = "tenant_id";
        private String rolesClaim = "roles";
        private Map<String, PrincipalBinding> principals = new HashMap<>();
        public String getActorClaim() { return actorClaim; }
        public void setActorClaim(String actorClaim) { this.actorClaim = actorClaim; }
        public String getTenantClaim() { return tenantClaim; }
        public void setTenantClaim(String tenantClaim) { this.tenantClaim = tenantClaim; }
        public String getRolesClaim() { return rolesClaim; }
        public void setRolesClaim(String rolesClaim) { this.rolesClaim = rolesClaim; }
        public Map<String, PrincipalBinding> getPrincipals() { return principals; }
        public void setPrincipals(Map<String, PrincipalBinding> principals) { this.principals = principals; }
    }

    public static class PrincipalBinding {
        private String actorId = "";
        private String tenantId = "";
        public String getActorId() { return actorId; }
        public void setActorId(String actorId) { this.actorId = actorId; }
        public String getTenantId() { return tenantId; }
        public void setTenantId(String tenantId) { this.tenantId = tenantId; }
    }

    public static class Payload {
        private int maxBytes = 65536;
        public int getMaxBytes() { return maxBytes; }
        public void setMaxBytes(int maxBytes) { this.maxBytes = maxBytes; }
    }

    public static class RateLimit {
        private boolean enabled = true;
        private int requestsPerMinute = 120;
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getRequestsPerMinute() { return requestsPerMinute; }
        public void setRequestsPerMinute(int requestsPerMinute) { this.requestsPerMinute = requestsPerMinute; }
    }

    /**
     * Durable replay/idempotency protection for appends. Keys are persisted in the
     * database rather than in memory, so a retry that lands on a different node - or
     * arrives after a restart - is still recognised as a replay instead of appending a
     * duplicate chain record.
     */
    public static class Idempotency {
        private boolean required;
        private int retentionHours = 24;
        public boolean isRequired() { return required; }
        public void setRequired(boolean required) { this.required = required; }
        public int getRetentionHours() { return retentionHours; }
        public void setRetentionHours(int retentionHours) { this.retentionHours = retentionHours; }
    }

    public static class Security {
        private final Basic basic = new Basic();
        private final Oidc oidc = new Oidc();
        private final Cors cors = new Cors();
        private final Tls tls = new Tls();
        private boolean csrfEnabled;
        public Basic getBasic() { return basic; }
        public Oidc getOidc() { return oidc; }
        public Cors getCors() { return cors; }
        public Tls getTls() { return tls; }
        public boolean isCsrfEnabled() { return csrfEnabled; }
        public void setCsrfEnabled(boolean csrfEnabled) { this.csrfEnabled = csrfEnabled; }
    }

    /**
     * Local-only HTTP Basic fallback. Blank passwords mean "generate a random one at
     * startup and log it" - dev convenience with no credential in the repository. The
     * production validator rejects this mechanism entirely.
     */
    public static class Basic {
        private boolean enabled = true;
        private String writerPassword = "";
        private String readerPassword = "";
        private String adminPassword = "";
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getWriterPassword() { return writerPassword; }
        public void setWriterPassword(String writerPassword) { this.writerPassword = writerPassword; }
        public String getReaderPassword() { return readerPassword; }
        public void setReaderPassword(String readerPassword) { this.readerPassword = readerPassword; }
        public String getAdminPassword() { return adminPassword; }
        public void setAdminPassword(String adminPassword) { this.adminPassword = adminPassword; }
    }

    public static class Oidc {
        private boolean enabled;
        private String issuerUri = "";
        private String jwkSetUri = "";
        private String audience = "";
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getIssuerUri() { return issuerUri; }
        public void setIssuerUri(String issuerUri) { this.issuerUri = issuerUri; }
        public String getJwkSetUri() { return jwkSetUri; }
        public void setJwkSetUri(String jwkSetUri) { this.jwkSetUri = jwkSetUri; }
        public String getAudience() { return audience; }
        public void setAudience(String audience) { this.audience = audience; }
    }

    public static class Cors {
        private List<String> allowedOrigins = new ArrayList<>();
        public List<String> getAllowedOrigins() { return allowedOrigins; }
        public void setAllowedOrigins(List<String> allowedOrigins) { this.allowedOrigins = allowedOrigins; }
    }

    public static class Tls {
        private boolean externallyTerminated;
        public boolean isExternallyTerminated() { return externallyTerminated; }
        public void setExternallyTerminated(boolean externallyTerminated) {
            this.externallyTerminated = externallyTerminated;
        }
    }
}
