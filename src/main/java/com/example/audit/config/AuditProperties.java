package com.example.audit.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "audit")
public class AuditProperties {
    private final Retention retention = new Retention();
    private final Signing signing = new Signing();

    public Retention getRetention() { return retention; }
    public Signing getSigning() { return signing; }

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

    public static class Signing {
        private String keyId = "local-dev-key";
        private String privateKeyBase64 = "";
        private String publicKeyBase64 = "";
        public String getKeyId() { return keyId; }
        public void setKeyId(String keyId) { this.keyId = keyId; }
        public String getPrivateKeyBase64() { return privateKeyBase64; }
        public void setPrivateKeyBase64(String privateKeyBase64) { this.privateKeyBase64 = privateKeyBase64; }
        public String getPublicKeyBase64() { return publicKeyBase64; }
        public void setPublicKeyBase64(String publicKeyBase64) { this.publicKeyBase64 = publicKeyBase64; }
    }
}
