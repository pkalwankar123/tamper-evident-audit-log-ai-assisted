package com.example.audit.security.keys;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Keys supplied by the surrounding platform - a KMS/secret manager projecting material
 * into the environment, a mounted secret, or a sealed config value.
 *
 * <p>This is the intended production backend. Rotation is explicitly <em>not</em>
 * supported here: the key lifecycle belongs to the external system, and letting the
 * application mint its own replacement would produce a key the platform does not know
 * about and cannot recover. Retired keys stay verifiable by being supplied alongside
 * the active one.
 */
public class ConfiguredSigningKeyStore implements SigningKeyStore {
    private final SigningKey active;
    private final List<SigningKey> keys;

    public ConfiguredSigningKeyStore(String keyId, String privateKeyBase64, String publicKeyBase64,
                                     List<SigningKey> retiredKeys) {
        if (keyId == null || keyId.isBlank()) {
            throw new IllegalStateException("audit.signing.key-id must be set when signing keys are configured");
        }
        this.active = new SigningKey(keyId, privateKeyBase64, publicKeyBase64, Instant.EPOCH);
        // Fail fast at startup rather than at the first export if the material is unusable.
        this.active.privateKey();
        this.active.publicKey();
        List<SigningKey> all = new java.util.ArrayList<>(retiredKeys == null ? List.of() : retiredKeys);
        all.add(this.active);
        this.keys = List.copyOf(all);
    }

    @Override
    public SigningKey activeKey() {
        return active;
    }

    @Override
    public Optional<SigningKey> findKey(String keyId) {
        return keys.stream().filter(key -> key.keyId().equals(keyId)).findFirst();
    }

    @Override
    public List<SigningKey> allKeys() {
        return keys;
    }

    @Override
    public SigningKey rotate() {
        throw new UnsupportedOperationException(
                "Signing keys are managed externally (KMS/secret store); rotate them there and redeploy "
                        + "with the new audit.signing.* values. The application will not mint a key the "
                        + "platform does not know about.");
    }

    @Override
    public String describe() {
        return "externally configured key store (active key id '" + active.keyId() + "')";
    }
}
