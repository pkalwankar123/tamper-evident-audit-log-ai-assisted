package com.example.audit.security.keys;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * A durable, file-backed key store.
 *
 * <p>This is the stand-in for a KMS/HSM in deployments that do not have one. It is not
 * pretending to be equivalent - the private key is at rest on local disk, protected
 * only by filesystem permissions - but it does provide the property that actually
 * matters for a tamper-evident log and that an ephemeral key cannot: the same key is
 * loaded again after a restart, so signatures issued before the restart still verify.
 * Swapping in a real KMS means implementing {@link SigningKeyStore} and nothing else.
 *
 * <p>Writes are done to a temporary file and then moved into place, so a crash midway
 * through a rotation cannot leave a truncated key file behind.
 */
public class FileSigningKeyStore implements SigningKeyStore {
    private final Path path;
    private final Clock clock;
    private final ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
    private StoreDocument document;

    public FileSigningKeyStore(Path path, String initialKeyId, Clock clock) {
        this.path = path;
        this.clock = clock;
        this.document = load().orElseGet(() -> {
            SigningKey generated = SigningKey.generate(
                    initialKeyId == null || initialKeyId.isBlank() ? newKeyId() : initialKeyId,
                    Instant.now(clock));
            StoreDocument fresh = new StoreDocument(generated.keyId(), new ArrayList<>(List.of(generated)));
            persist(fresh);
            return fresh;
        });
    }

    @Override
    public synchronized SigningKey activeKey() {
        return findKey(document.activeKeyId())
                .orElseThrow(() -> new IllegalStateException(
                        "Key store at " + path + " has no key matching its active key id"));
    }

    @Override
    public synchronized Optional<SigningKey> findKey(String keyId) {
        return document.keys().stream().filter(key -> key.keyId().equals(keyId)).findFirst();
    }

    @Override
    public synchronized List<SigningKey> allKeys() {
        return List.copyOf(document.keys());
    }

    @Override
    public synchronized SigningKey rotate() {
        SigningKey generated = SigningKey.generate(newKeyId(), Instant.now(clock));
        List<SigningKey> keys = new ArrayList<>(document.keys());
        keys.add(generated);
        StoreDocument updated = new StoreDocument(generated.keyId(), keys);
        persist(updated);
        this.document = updated;
        return generated;
    }

    @Override
    public String describe() {
        return "file key store at " + path;
    }

    private Optional<StoreDocument> load() {
        if (!Files.exists(path)) {
            return Optional.empty();
        }
        try {
            StoreDocument loaded = mapper.readValue(Files.readAllBytes(path), StoreDocument.class);
            if (loaded == null || loaded.keys() == null || loaded.keys().isEmpty()) {
                throw new IllegalStateException("Signing key store at " + path + " is present but contains no keys");
            }
            return Optional.of(loaded);
        } catch (IOException exception) {
            throw new UncheckedIOException("Unable to read the signing key store at " + path, exception);
        }
    }

    private void persist(StoreDocument toWrite) {
        try {
            Path parent = path.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path temporary = Files.createTempFile(parent, "signing-keys", ".tmp");
            Files.write(temporary, mapper.writeValueAsBytes(toWrite));
            restrictPermissions(temporary);
            Files.move(temporary, path, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException exception) {
            throw new UncheckedIOException("Unable to write the signing key store at " + path, exception);
        }
    }

    /**
     * Best effort owner-only permissions. Silently skipped on filesystems without POSIX
     * permission support (Windows), where access control is expected to come from the
     * directory ACL instead.
     */
    private static void restrictPermissions(Path target) {
        try {
            Set<PosixFilePermission> ownerOnly = EnumSet.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(target, ownerOnly);
        } catch (IOException | UnsupportedOperationException ignored) {
            // Not a POSIX filesystem; directory ACLs govern access instead.
        }
    }

    /**
     * Unique by construction. An id derived from a timestamp can repeat when two
     * rotations land in the same millisecond, and a duplicate key id would make
     * signature-to-key lookup ambiguous - exactly the failure rotation exists to avoid.
     */
    private static String newKeyId() {
        return "audit-signing-" + java.util.UUID.randomUUID();
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record StoreDocument(String activeKeyId, List<SigningKey> keys) {
    }
}
