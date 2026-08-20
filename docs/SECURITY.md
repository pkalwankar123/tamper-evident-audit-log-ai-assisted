# Security Design

How each control works, where it is enforced, and what proves it. Every claim below
names the test that backs it; if a claim has no test, it says so.

## 1. Identity: derived, never supplied

No endpoint accepts an `actorId` or `tenantId` for a security decision. The request
records no longer have those fields - the concept was removed from the API rather than
validated at it, because a field a caller can populate is a field a caller can lie in,
and validation only narrows the lie.

`ActorResolver` produces an `AuthenticatedActor(username, actorId, tenantId, admin)`
from the authenticated principal and nothing else:

| Mechanism | actorId | tenantId | roles |
|---|---|---|---|
| OIDC / JWT (production) | `sub` claim | `tenant_id` claim | `roles` claim + OAuth2 scopes |
| HTTP Basic (dev/test only) | `audit.identity.principals.<user>.actor-id` | `...tenant-id` | in-memory user authorities |

Claim names are configurable so the service adapts to the IdP rather than the reverse.
A principal with no resolvable actor **or** tenant is denied outright - there is no
default tenant and no unrestricted principal.

The one surviving `actorId` query parameter, on read and export, is a filter applied
*within* data the caller may already see. `AuditAccessPolicy` re-checks it and denies
rather than widening scope; a non-admin naming another actor gets 403, not a silently
rewritten filter that would return a confusing empty page.

*Proven by:* `AuditAccessPolicyTest`, `OidcAuthenticationTest`,
`ServiceLayerAuthorizationTest.appendDerivesIdentityFromPrincipal`.

## 2. Authorization: two axes, enforced at the service layer

- **Tenant** is absolute. Nobody - administrators included - reads, verifies, exports,
  archives or redacts outside their own tenant.
- **Actor** applies within a tenant. An administrator may act across actors; everyone
  else is confined to their own.

Enforcement lives in `AuditAccessPolicy`, called from `AuditService`, `ExportService`
and `CheckpointService` - not in the controller. Role matchers in `SecurityConfig` are a
coarse first gate; they cannot express "whose data is this", because that depends on the
record. Putting the decision next to the data means it holds for any future caller: a
scheduled job, a message consumer, a second controller.

*Proven by:* `ServiceLayerAuthorizationTest` (18 tests driving the services directly,
no HTTP), `TenantIsolationHttpTest`, `AuditAccessPolicyTest`.

## 3. Authentication and secrets

**No credential, key or identity binding exists in `application.properties`, and no
`:default` fallback stands in for one.** Running with no profile yields a service with
no identity bindings, so every request is denied - an unconfigured deployment refuses
work rather than guessing.

- **Production** uses OIDC/OAuth2 bearer tokens only. Credential handling, session
  lifetime and **MFA belong to the identity provider**; this service validates tokens
  (signature, issuer, audience, expiry) and derives identity from claims.
- **Development** may use HTTP Basic. The three local users have no configured password;
  `SecurityConfig` generates a random one per run and logs it, the way Spring Boot
  handles its own default user. There is no fixed secret to leak.
- **Tests** use explicit fixture passwords in `src/test/resources/application.properties`
  against a throwaway in-memory database.

`ProductionSecurityValidator` runs at startup under the `prod` profile and aborts,
listing every problem at once, if any of these hold: OIDC disabled or without an issuer;
Basic auth still enabled; ephemeral signing keys; no durable key source; configured keys
without a key id; TLS neither terminated locally nor declared as terminated upstream;
wildcard CORS; H2 console, Swagger or API docs enabled; `ddl-auto` other than
`none`/`validate`; an H2 datasource.

That second mechanism exists because unresolvable placeholders alone are not enough - an
empty environment variable satisfies a placeholder, and "Basic auth is still on" is not
placeholder-shaped at all.

*Proven by:* `ProductionSecurityValidatorTest` (13 tests, one per rule).

## 4. Signing keys: durable, rotatable, never ephemeral by accident

`SigningKeyStore` is the seam that makes a KMS/HSM, an injected secret and a local file
interchangeable. Three implementations, selected in a fixed order:

1. `ConfiguredSigningKeyStore` - material injected from a KMS/secret manager. The
   production path. Local rotation is refused: the key lifecycle belongs to the external
   system, and minting a replacement would produce a key the platform cannot recover.
2. `FileSigningKeyStore` - a durable local file, written atomically via a temp file and
   move. Not a KMS, but it provides the property that matters: the same key loads again
   after a restart.
3. `EphemeralSigningKeyStore` - opt-in only, for tests.

If none is configured, **startup fails**. The previous behaviour - quietly generating a
throwaway keypair whenever the configured key was blank - meant a restart silently
invalidated every bundle the service had ever signed and every stored checkpoint.
Nothing errored; the signatures just stopped verifying.

Every signature names the key id that produced it, so rotation retires a key without
invalidating evidence signed under it.

*Proven by:* `SigningKeyStoreTest` (restart persistence, rotation, retired-key
verification, no fallback on unknown key id, ephemeral non-persistence, fail-closed
startup).

## 5. Integrity

**Per-tenant hash chain.** Each record stores `previousHash` and `recordHash` over
`(tenantId, index, eventType, actorId, resourceType, resourceId, timestamp, ingestedAt,
payloadCommitment, previousHash)`. Chains are partitioned per tenant because a
tenant-scoped verification over a shared chain would see a gap wherever another tenant's
records were filtered out.

**Distributed append serialization.** Appends take a `PESSIMISTIC_WRITE` row lock on the
tenant's `chain_heads` row, and the head advances in the same transaction that inserts
the record. The database - the one component every node genuinely shares - orders
concurrent appends.

This replaced a `synchronized` block that was wrong twice over: it did nothing across
nodes, and because Spring wraps the method in a transactional proxy the monitor was
released before commit, so even single-node writers could interleave between hash
computation and commit. Because the head advances transactionally, a failed append
consumes no index and leaves no gap.

**Redaction ledger.** Redaction rewrites the payload and appends a hash-linked entry
recording the transition. Verification replays the ledger, so a legitimate redaction
verifies and an unexplained payload change does not.

**Signed checkpoints.** Link checking is satisfied by *any* internally consistent chain,
including one an attacker rebuilt after deleting records. A checkpoint signs
`(tenantId, chainIndex, recordHash, createdAt)`, giving verification an anchor outside
the data being verified. Verification reports `CHECKPOINT_MISSING_RECORDS` on truncation,
`CHECKPOINT_MISMATCH` on a rewrite, and `CHECKPOINT_SIGNATURE_INVALID` on a forged
checkpoint.

*Proven by:* `AuditLogIntegrationTest` (payload edit, link rewrite via direct SQL,
deletion), `CheckpointIntegrityTest` (truncation, rewrite, forgery),
`AppendConcurrencyAndRollbackTest` (concurrency, rollback).

## 6. Retention and archive

Records have exactly two states: active, then archived once older than
`audit.retention.days`. Archiving sets a flag on a field no hash covers, so an archived
record still verifies and still exports. **Nothing in this service deletes an audit
record** - hard deletion would break the chain by construction and is not offered.

Both entry points are tenant-scoped: the scheduled sweep runs per tenant under a system
identity through the same authorization path a human would; the on-demand trigger
requires `ROLE_AUDIT_ADMIN`. The archive response reports whether the chain still
verifies afterwards.

*Proven by:* `RetentionAndArchiveTest`, plus the cross-tenant cases in
`TenantIsolationHttpTest.archiveDoesNotCrossTenants`.

## 7. Export

Admin-only and confined to the caller's tenant. The bundle spans the contiguous
chain-index range covering the selection - intervening records are included and flagged
`selected=false`, because without them a recipient cannot check the hash links between
the selected ones. Each record carries its redaction ledger.

`ExportCanonicalForm` defines the signed bytes as an explicit line-oriented format
rather than "whatever Jackson emits", because the latter is not independently
reproducible - a recipient would have to replicate one serializer's field ordering and
date handling exactly.

`ExportVerifier` is the code a recipient runs. It touches no database and re-derives
five things from the bundle alone: each `recordHash`, the links between consecutive
records, each payload against its commitment (through the ledger where present), the
manifest hash, and the Ed25519 signature. `verifyAgainstTrustedKey` exists separately
from `verify` because checking a bundle against its own embedded key proves only
internal consistency - an attacker can produce a perfectly self-consistent bundle with
their own keypair, which the test suite demonstrates.

*Proven by:* `ExportVerificationTest` (11 tests, including exact segment cardinality,
altered payload, altered field, dropped record, forged signature, untrusted key).

## 8. API security

| Control | Decision |
|---|---|
| **CSRF** | Explicitly disabled. Stateless API, per-request bearer/Basic authentication, no session cookie, so no ambient credential for a cross-site request to ride. `audit.security.csrf-enabled` re-enables it if the service is ever fronted by a cookie/session browser flow - the condition that would make CSRF applicable. |
| **CORS** | Deny by default. No origins configured means no allowed origin at all. Never wildcards, never `allowCredentials`. `*` is rejected outright in production. |
| **Rate limiting** | Per-principal fixed window, configurable, positioned after authentication so it keys on the user rather than only the IP. In-memory - see limitations. |
| **Request size** | `RequestSizeLimitFilter` rejects on declared `Content-Length` before the body is parsed (413); the service-layer check on `audit.payload.max-bytes` remains authoritative for requests that omit or understate it; the container caps what it will swallow. |
| **Pagination** | Strict bounds, rejected rather than clamped, so a caller is told their request was wrong instead of silently receiving different data. |
| **Idempotency / replay** | Optional `Idempotency-Key` header, persisted in the database. A replay returns the original record with `200` and `Idempotent-Replay: true`; reuse with a different body is `409`. Durable and tenant-scoped, so a retry landing on another node or after a restart is still recognised. |
| **Error responses** | Authorization denials return a fixed message. Internal messages name tenants and actor ids, which would turn an error response into a probe for what exists. |

## Known limitations

Stated plainly rather than omitted.

- **Rate limiting is per-node and in-memory.** It resets on restart and is not shared
  across a cluster. A real deployment needs a shared store or an ingress-level limiter.
- **No token revocation.** Tokens are valid until expiry; revocation would need
  introspection or a deny list.
- **`FileSigningKeyStore` is not a KMS.** The private key sits on local disk protected
  by filesystem permissions, and the POSIX permission tightening is skipped on Windows.
- **Tests run against H2, not PostgreSQL.** Lock and constraint semantics are close but
  not identical.
- **Multi-node concurrency is not tested.** The mechanism is a database row lock that
  would serialize nodes, but only single-JVM concurrency has been demonstrated.
- **Checkpoints are created on demand, not automatically.** Nothing schedules them, so
  the truncation window is as large as the gap between manual checkpoints.
- **Redaction is limited to object-field JSON Pointers**; array elements are not
  supported.
- **No schema migrations.** Production requires `ddl-auto=validate`, but no
  Flyway/Liquibase migrations are provided, so the schema must be created out of band.

Human sign-off is required before changing canonicalization, hash inputs, signing keys,
redaction semantics, retention, identity derivation or authorization - each can
invalidate historical evidence or access-control correctness.
