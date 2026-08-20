package com.example.audit.service;

import com.example.audit.security.keys.SigningKey;
import com.example.audit.security.keys.SigningKeyStore;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Optional;

/**
 * Ed25519 signing and verification over the configured {@link SigningKeyStore}.
 *
 * <p>Signatures always name the key that produced them, so verification of older
 * evidence keeps working across a rotation: {@link #verify} looks the key up by id
 * rather than assuming the currently active one.
 */
@Service
public class SigningService {
    private final SigningKeyStore keyStore;

    public SigningService(SigningKeyStore keyStore) {
        this.keyStore = keyStore;
    }

    public String sign(String content) {
        SigningKey key = keyStore.activeKey();
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(key.privateKey());
            signature.update(content.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to sign with key '" + key.keyId() + "'", exception);
        }
    }

    /** Verifies against whichever key produced the signature, active or retired. */
    public boolean verify(String content, String signatureBase64, String keyId) {
        Optional<SigningKey> key = keyStore.findKey(keyId);
        return key.isPresent() && verifyWith(key.get().publicKey(), content, signatureBase64);
    }

    /** Verification against an externally supplied public key, as a recipient would do. */
    public static boolean verifyWith(PublicKey publicKey, String content, String signatureBase64) {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initVerify(publicKey);
            signature.update(content.getBytes(StandardCharsets.UTF_8));
            return signature.verify(Base64.getDecoder().decode(signatureBase64));
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            return false;
        }
    }

    public String publicKeyBase64() {
        return keyStore.activeKey().publicKeyBase64();
    }

    public String keyId() {
        return keyStore.activeKey().keyId();
    }

    public Optional<String> publicKeyBase64(String keyId) {
        return keyStore.findKey(keyId).map(SigningKey::publicKeyBase64);
    }

    public SigningKey rotateKey() {
        return keyStore.rotate();
    }
}
