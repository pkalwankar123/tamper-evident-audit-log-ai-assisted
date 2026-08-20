package com.example.audit;

import com.example.audit.config.AuditProperties;
import com.example.audit.config.SigningKeyStoreConfig;
import com.example.audit.security.keys.ConfiguredSigningKeyStore;
import com.example.audit.security.keys.EphemeralSigningKeyStore;
import com.example.audit.security.keys.FileSigningKeyStore;
import com.example.audit.security.keys.SigningKey;
import com.example.audit.service.SigningService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Key durability and rotation - the properties that decide whether signed evidence
 * survives ordinary operations.
 *
 * <p>The failure these tests exist to prevent is subtle and used to be the default
 * behaviour: with no key configured the service minted a fresh keypair on every boot, so
 * a restart silently invalidated every bundle it had ever signed. Nothing failed, nothing
 * logged an error - the signatures simply stopped verifying. "Restart" is modelled here
 * by constructing a second store over the same path, which is exactly what a new process
 * does.
 */
class SigningKeyStoreTest {

    @Test
    @DisplayName("a file-backed key survives a restart, and signatures issued before it still verify")
    void keyAndSignaturesSurviveRestart(@TempDir Path directory) {
        Path keyFile = directory.resolve("signing-keys.json");

        FileSigningKeyStore before = new FileSigningKeyStore(keyFile, "initial-key", Clock.systemUTC());
        String signature = new SigningService(before).sign("evidence-payload");
        String keyIdBefore = before.activeKey().keyId();
        String publicKeyBefore = before.activeKey().publicKeyBase64();

        // A new process starting against the same store.
        FileSigningKeyStore after = new FileSigningKeyStore(keyFile, "initial-key", Clock.systemUTC());

        assertThat(after.activeKey().keyId()).isEqualTo(keyIdBefore);
        assertThat(after.activeKey().publicKeyBase64()).isEqualTo(publicKeyBefore);
        assertThat(new SigningService(after).verify("evidence-payload", signature, keyIdBefore)).isTrue();
    }

    @Test
    @DisplayName("the key file is created once and reused, not regenerated")
    void keyFileIsCreatedOnceAndReused(@TempDir Path directory) throws Exception {
        Path keyFile = directory.resolve("nested").resolve("signing-keys.json");

        new FileSigningKeyStore(keyFile, "k", Clock.systemUTC());
        assertThat(Files.exists(keyFile)).isTrue();
        byte[] first = Files.readAllBytes(keyFile);

        new FileSigningKeyStore(keyFile, "k", Clock.systemUTC());
        assertThat(Files.readAllBytes(keyFile)).isEqualTo(first);
    }

    @Test
    @DisplayName("rotation activates a new key while earlier signatures keep verifying")
    void rotationRetainsEarlierKeysForVerification(@TempDir Path directory) {
        Path keyFile = directory.resolve("signing-keys.json");
        FileSigningKeyStore store = new FileSigningKeyStore(keyFile, "original-key", Clock.systemUTC());
        SigningService signing = new SigningService(store);

        String oldKeyId = store.activeKey().keyId();
        String signedBeforeRotation = signing.sign("older-evidence");

        SigningKey rotated = store.rotate();

        assertThat(rotated.keyId()).isNotEqualTo(oldKeyId);
        assertThat(store.activeKey().keyId()).isEqualTo(rotated.keyId());
        assertThat(store.allKeys()).hasSize(2);
        // The retired key is still resolvable, so evidence signed under it stays valid.
        assertThat(store.findKey(oldKeyId)).isPresent();
        assertThat(signing.verify("older-evidence", signedBeforeRotation, oldKeyId)).isTrue();
        // And the new key genuinely is a different key.
        assertThat(signing.verify("older-evidence", signedBeforeRotation, rotated.keyId())).isFalse();
    }

    @Test
    @DisplayName("a rotation is persisted, so the new key is still active after a restart")
    void rotationSurvivesRestart(@TempDir Path directory) {
        Path keyFile = directory.resolve("signing-keys.json");
        FileSigningKeyStore store = new FileSigningKeyStore(keyFile, "original-key", Clock.systemUTC());
        String originalKeyId = store.activeKey().keyId();
        SigningKey rotated = store.rotate();
        String signedAfterRotation = new SigningService(store).sign("newer-evidence");

        FileSigningKeyStore restarted = new FileSigningKeyStore(keyFile, "original-key", Clock.systemUTC());

        assertThat(restarted.activeKey().keyId()).isEqualTo(rotated.keyId());
        assertThat(restarted.findKey(originalKeyId)).isPresent();
        assertThat(new SigningService(restarted).verify("newer-evidence", signedAfterRotation, rotated.keyId()))
                .isTrue();
    }

    @Test
    @DisplayName("verification against an unknown key id fails rather than falling back to the active key")
    void unknownKeyIdDoesNotFallBack(@TempDir Path directory) {
        FileSigningKeyStore store =
                new FileSigningKeyStore(directory.resolve("keys.json"), "k", Clock.systemUTC());
        SigningService signing = new SigningService(store);
        String signature = signing.sign("payload");

        assertThat(signing.verify("payload", signature, "no-such-key-id")).isFalse();
        assertThat(signing.verify("payload", signature, store.activeKey().keyId())).isTrue();
    }

    @Test
    @DisplayName("externally managed keys refuse local rotation")
    void configuredStoreRefusesLocalRotation() {
        SigningKey material = SigningKey.generate("kms-key-1", Instant.now());
        ConfiguredSigningKeyStore store = new ConfiguredSigningKeyStore("kms-key-1",
                material.privateKeyBase64(), material.publicKeyBase64(), java.util.List.of());

        assertThat(store.activeKey().keyId()).isEqualTo("kms-key-1");
        assertThatThrownBy(store::rotate)
                .isInstanceOf(UnsupportedOperationException.class)
                .hasMessageContaining("managed externally");
    }

    @Test
    @DisplayName("unusable configured key material fails at startup, not at the first export")
    void unusableConfiguredMaterialFailsFast() {
        assertThatThrownBy(() -> new ConfiguredSigningKeyStore("bad-key", "not-base64-key", "also-not", null))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> {
            SigningKey material = SigningKey.generate("k", Instant.now());
            new ConfiguredSigningKeyStore("", material.privateKeyBase64(), material.publicKeyBase64(), null);
        }).isInstanceOf(IllegalStateException.class).hasMessageContaining("key-id");
    }

    @Test
    @DisplayName("an ephemeral store does not survive a restart - which is why it is not the default")
    void ephemeralStoreDoesNotSurviveRestart() {
        EphemeralSigningKeyStore first = new EphemeralSigningKeyStore("ephemeral");
        String signature = new SigningService(first).sign("payload");

        EphemeralSigningKeyStore second = new EphemeralSigningKeyStore("ephemeral");

        assertThat(second.activeKey().publicKeyBase64()).isNotEqualTo(first.activeKey().publicKeyBase64());
        assertThat(new SigningService(second).verify("payload", signature, "ephemeral")).isFalse();
    }

    @Test
    @DisplayName("with no key source configured, startup fails instead of minting a throwaway key")
    void noKeySourceFailsClosed() {
        AuditProperties properties = new AuditProperties();

        assertThatThrownBy(() -> new SigningKeyStoreConfig().signingKeyStore(properties))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No signing key source is configured");
    }

    @Test
    @DisplayName("the configured key source wins over the file store, and ephemeral is last")
    void keySourceSelectionOrderIsExplicit(@TempDir Path directory) {
        SigningKey material = SigningKey.generate("kms-key", Instant.now());
        AuditProperties properties = new AuditProperties();
        properties.getSigning().setKeyId("kms-key");
        properties.getSigning().setPrivateKeyBase64(material.privateKeyBase64());
        properties.getSigning().setPublicKeyBase64(material.publicKeyBase64());
        properties.getSigning().setStorePath(directory.resolve("unused.json").toString());
        properties.getSigning().setAllowEphemeral(true);

        assertThat(new SigningKeyStoreConfig().signingKeyStore(properties))
                .isInstanceOf(ConfiguredSigningKeyStore.class);

        properties.getSigning().setPrivateKeyBase64("");
        properties.getSigning().setPublicKeyBase64("");
        assertThat(new SigningKeyStoreConfig().signingKeyStore(properties))
                .isInstanceOf(FileSigningKeyStore.class);

        properties.getSigning().setStorePath("");
        assertThat(new SigningKeyStoreConfig().signingKeyStore(properties))
                .isInstanceOf(EphemeralSigningKeyStore.class);
    }
}
