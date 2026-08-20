package com.example.audit.security.keys;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;

/**
 * One Ed25519 signing key, identified by a stable {@code keyId}.
 *
 * <p>The {@code keyId} is what makes rotation workable: every signature the service
 * emits carries the id of the key that produced it, so a bundle signed before a
 * rotation stays verifiable afterwards by looking the retired key up rather than
 * assuming the current one.
 */
public record SigningKey(String keyId, String privateKeyBase64, String publicKeyBase64, Instant createdAt) {

    public static SigningKey generate(String keyId, Instant createdAt) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
            KeyPair pair = generator.generateKeyPair();
            return new SigningKey(keyId,
                    Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()),
                    Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()),
                    createdAt);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to generate an Ed25519 signing key", exception);
        }
    }

    public PrivateKey privateKey() {
        try {
            return KeyFactory.getInstance("Ed25519")
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyBase64)));
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new IllegalStateException("Signing key '" + keyId + "' has an unusable private key", exception);
        }
    }

    public PublicKey publicKey() {
        try {
            return KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyBase64)));
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new IllegalStateException("Signing key '" + keyId + "' has an unusable public key", exception);
        }
    }
}
