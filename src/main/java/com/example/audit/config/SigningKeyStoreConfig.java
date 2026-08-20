package com.example.audit.config;

import com.example.audit.security.keys.ConfiguredSigningKeyStore;
import com.example.audit.security.keys.EphemeralSigningKeyStore;
import com.example.audit.security.keys.FileSigningKeyStore;
import com.example.audit.security.keys.SigningKeyStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Path;
import java.time.Clock;
import java.util.List;

/**
 * Selects the signing key backend, in a deliberate order, and fails closed.
 *
 * <ol>
 *   <li>Explicit key material (KMS/secret-store injected) - the production path.</li>
 *   <li>A durable file store - a real, restart-surviving fallback for deployments
 *       without a KMS.</li>
 *   <li>Ephemeral in-memory keys - only if explicitly opted into.</li>
 * </ol>
 *
 * <p>If none of those is configured, startup fails with an actionable message. The
 * previous behaviour - quietly generating a throwaway keypair - is gone: it made every
 * export signed before a restart permanently unverifiable, which defeats the point of
 * signing the export at all.
 */
@Configuration
public class SigningKeyStoreConfig {
    private static final Logger LOGGER = LoggerFactory.getLogger(SigningKeyStoreConfig.class);

    @Bean
    public SigningKeyStore signingKeyStore(AuditProperties properties) {
        AuditProperties.Signing signing = properties.getSigning();
        boolean hasMaterial = !signing.getPrivateKeyBase64().isBlank() && !signing.getPublicKeyBase64().isBlank();

        SigningKeyStore store;
        if (hasMaterial) {
            store = new ConfiguredSigningKeyStore(signing.getKeyId(), signing.getPrivateKeyBase64(),
                    signing.getPublicKeyBase64(), List.of());
        } else if (!signing.getStorePath().isBlank()) {
            store = new FileSigningKeyStore(Path.of(signing.getStorePath()), signing.getKeyId(), Clock.systemUTC());
        } else if (signing.isAllowEphemeral()) {
            store = new EphemeralSigningKeyStore(signing.getKeyId());
            LOGGER.warn("Using an EPHEMERAL signing key. Signatures produced now will NOT verify after a "
                    + "restart. Set audit.signing.private-key-base64/public-key-base64 (KMS-injected) or "
                    + "audit.signing.store-path for any deployment whose exports must remain verifiable.");
        } else {
            throw new IllegalStateException("""
                    No signing key source is configured, and ephemeral keys are not permitted.
                    Configure exactly one of:
                      audit.signing.private-key-base64 + audit.signing.public-key-base64 + audit.signing.key-id
                          (production: injected from a KMS/secret store), or
                      audit.signing.store-path  (durable local key file), or
                      audit.signing.allow-ephemeral=true  (tests and throwaway local runs ONLY - signatures
                          do not survive a restart, and the prod profile rejects this flag).""");
        }
        LOGGER.info("Audit export signing initialised: {}", store.describe());
        return store;
    }
}
