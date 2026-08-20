package com.example.audit.security.keys;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * An in-memory key store that exists only for tests and throwaway local runs.
 *
 * <p>It is never selected implicitly. {@code SigningKeyStoreConfig} builds it only when
 * {@code audit.signing.allow-ephemeral=true} is set explicitly, and the production
 * validator rejects that flag outright, so there is no path by which a production
 * deployment silently ends up with a key that disappears on restart.
 */
public class EphemeralSigningKeyStore implements SigningKeyStore {
    private final List<SigningKey> keys = new ArrayList<>();
    private String activeKeyId;

    public EphemeralSigningKeyStore(String keyId) {
        SigningKey generated = SigningKey.generate(
                keyId == null || keyId.isBlank() ? "ephemeral-key" : keyId, Instant.now());
        keys.add(generated);
        this.activeKeyId = generated.keyId();
    }

    @Override
    public synchronized SigningKey activeKey() {
        return findKey(activeKeyId).orElseThrow();
    }

    @Override
    public synchronized Optional<SigningKey> findKey(String keyId) {
        return keys.stream().filter(key -> key.keyId().equals(keyId)).findFirst();
    }

    @Override
    public synchronized List<SigningKey> allKeys() {
        return List.copyOf(keys);
    }

    @Override
    public synchronized SigningKey rotate() {
        SigningKey generated = SigningKey.generate("ephemeral-key-" + (keys.size() + 1), Instant.now());
        keys.add(generated);
        activeKeyId = generated.keyId();
        return generated;
    }

    @Override
    public String describe() {
        return "EPHEMERAL in-memory key store (not durable - test/throwaway use only)";
    }
}
