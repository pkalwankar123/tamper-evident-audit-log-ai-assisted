package com.example.audit.security.keys;

import java.util.List;
import java.util.Optional;

/**
 * Where signing key material lives.
 *
 * <p>This interface is the seam that lets the service treat a KMS/HSM, an
 * environment-injected secret, and a durable local file identically. The important
 * property for a tamper-evident log is not which backend is used but that the key
 * <em>survives a restart</em>: a key that is regenerated on boot silently invalidates
 * every signature the service has ever produced, so every previously exported bundle
 * and every stored checkpoint becomes unverifiable. The previous implementation did
 * exactly that whenever the configured key was blank; no implementation here does.
 *
 * <p>Rotation is part of the contract rather than an afterthought. Retired keys are
 * retained for verification, so rotating does not invalidate existing evidence.
 */
public interface SigningKeyStore {

    /** The key new signatures are produced with. */
    SigningKey activeKey();

    /** Looks up any key, active or retired, by the id embedded in a signature. */
    Optional<SigningKey> findKey(String keyId);

    /** All keys held, active and retired. */
    List<SigningKey> allKeys();

    /**
     * Promotes a freshly generated key to active, retaining the previous one for
     * verification. Backends that manage rotation externally (a KMS) reject this.
     */
    SigningKey rotate();

    /** A short description of the backend, used in startup logging and diagnostics. */
    String describe();
}
