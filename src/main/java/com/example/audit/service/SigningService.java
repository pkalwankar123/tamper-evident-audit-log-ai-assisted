package com.example.audit.service;

import com.example.audit.config.AuditProperties;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
public class SigningService {
    private final AuditProperties properties;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public SigningService(AuditProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    void initialize() {
        try {
            String privateValue = properties.getSigning().getPrivateKeyBase64();
            String publicValue = properties.getSigning().getPublicKeyBase64();
            if (!privateValue.isBlank() && !publicValue.isBlank()) {
                KeyFactory factory = KeyFactory.getInstance("Ed25519");
                privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateValue)));
                publicKey = factory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicValue)));
            } else {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
                KeyPair pair = generator.generateKeyPair();
                privateKey = pair.getPrivate();
                publicKey = pair.getPublic();
            }
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to initialize export signing keys", exception);
        }
    }

    public String sign(String content) {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(privateKey);
            signature.update(content.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to sign export", exception);
        }
    }

    public String publicKeyBase64() {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public String keyId() {
        return properties.getSigning().getKeyId();
    }
}
