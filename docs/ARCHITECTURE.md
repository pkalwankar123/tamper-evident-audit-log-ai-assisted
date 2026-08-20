# Architecture Overview

## Components

| Component | Responsibility |
|---|---|
| `AuditController` | HTTP boundary. Resolves the caller's identity and delegates; holds no authorization logic of its own beyond pagination validation. |
| `ActorResolver` | Derives `AuthenticatedActor(username, actorId, tenantId, admin)` from token claims or the principal binding table. The only source of identity. |
| `AuditAccessPolicy` | The single place where "may this actor touch this data" is decided. Called from the services. |
| `AuditService` | Query, redaction, verification, archival. Consults the policy before touching data. |
| `AuditAppender` | The one transactional unit that extends a chain by one record. |
| `ChainHeadService` | Bootstraps the per-tenant chain-head row that appends lock against. |
| `CheckpointService` | Creates and lists signed chain checkpoints. |
| `ExportService` / `ExportCanonicalForm` / `ExportVerifier` | Builds, canonicalizes and independently verifies evidence bundles. |
| `SigningService` / `SigningKeyStore` | Ed25519 signing and verification over a pluggable, durable key backend. |
| `RetentionService` | Scheduled and on-demand archival. |
| `RateLimitFilter` / `RequestSizeLimitFilter` | Per-principal rate limiting; pre-parse request size rejection. |
| `ProductionSecurityValidator` | Startup gate for the `prod` profile. |

## Why authorization lives in the service layer

Role matchers in `SecurityConfig` answer "may this role reach this endpoint". They cannot
answer "whose data is this", because that depends on the record being touched. Putting
ownership and tenant checks in `AuditAccessPolicy`, invoked from the services, means the
guarantee holds for any caller - a future controller, a scheduled job, a message consumer
- and it makes the rules testable without HTTP. `ServiceLayerAuthorizationTest` drives
the services directly for exactly that reason.

## Data model

| Table | Purpose |
|---|---|
| `audit_records` | The chain. Unique on `(tenant_id, chain_index)`. |
| `redaction_entries` | Hash-linked ledger of payload transitions, one chain per record. |
| `chain_heads` | One row per tenant. The append serialization point and the current head pointer. |
| `chain_checkpoints` | Signed commitments to `(chain_index, record_hash)`. |
| `idempotency_records` | Durable replay protection. Unique on `(tenant_id, idempotency_key)`. |

## Chain design

Chains are **partitioned per tenant**. A shared global chain cannot support a
tenant-scoped verification: the verifier would see a gap wherever another tenant's
records were filtered out, and reporting tampering for correct data is worse than not
verifying at all. Partitioning along the same boundary the authorization model already
uses keeps both coherent.

Each record stores:

```
payloadCommitment = SHA-256(canonical payload JSON)
recordHash        = SHA-256(tenantId | chainIndex | eventType | actorId | resourceType
                            | resourceId | timestamp | ingestedAt | payloadCommitment
                            | previousHash)
```

The genesis predecessor is 64 zeroes. JSON is serialized with ordered map keys before
hashing. SHA-256 was chosen for broad platform support and collision resistance.

Hashing provides tamper *evidence*, not authentication or prevention. Database access
controls, restricted roles and external anchoring are still required.

## Append serialization

Every append takes a `PESSIMISTIC_WRITE` lock on the tenant's `chain_heads` row and
advances the head **inside the same transaction** that inserts the record.

This replaced a JVM `synchronized` block plus a `lockTail()` query, which was inadequate
in three distinct ways:

1. It served no purpose across nodes - a second JVM shared no monitor.
2. Spring wraps the method in a transactional proxy, so the monitor was released before
   commit; even single-node writers could interleave between hash computation and commit.
3. On an empty table there was no tail row to lock, so the very first concurrent appends
   raced with nothing preventing them.

Because the head advances transactionally, a rolled-back append consumes no index and
leaves no gap - the property `AppendRollbackTest` asserts.

The chain-head row is created in its own `REQUIRES_NEW` transaction, with the
duplicate-key failure caught *outside* that transaction. Catching it inside leaves the
transaction rollback-only and throws at commit, which is precisely how the first version
of this code failed under concurrency.

## Redaction design

`payload_json` may change only through the redaction API. The immutable chain record
continues to commit to the *original* payload. Each ledger entry records the record id,
JSON Pointer, reason, the actor derived from the principal, prior payload hash, new
payload hash, predecessor entry hash, and its own hash.

Verification checks, in order: the main chain; every redaction transition and ledger
link; and that the current payload hash equals the latest authorized redaction result.

This removes sensitive cleartext from the active row while retaining evidence that the
record originally committed to some value. It does **not** remove copies from backups,
database logs, caches, or bundles exported earlier.

## Checkpoints

Link checking is satisfied by any internally consistent chain, including one an attacker
rebuilt after deleting records - every remaining link verifies, and the evidence is
quietly gone. A checkpoint signs `(tenantId, chainIndex, recordHash, createdAt)`, giving
verification an anchor outside the data it is checking. Verification reports
`CHECKPOINT_MISSING_RECORDS` for truncation, `CHECKPOINT_MISMATCH` for a rewrite, and
`CHECKPOINT_SIGNATURE_INVALID` for a forged checkpoint.

Checkpoints are stored in the same database as the chain, which bounds what they can
prove: an attacker with full write access can delete the checkpoints too. Anchoring them
externally is the production step.

## Retention

Archival sets `archived=true` and touches no hashed field, so archived records still
verify and still export. Queries exclude them unless `includeArchived=true`; verification
always includes them, because skipping them would leave archived records modifiable
without detection. No path deletes an audit record.

## Export

A bundle spans the contiguous chain-index range covering the selection. Non-matching
records inside that range are included with `selected=false` - not padding, but the
material a recipient needs to check the hash links between the selected records. Each
record carries its redaction ledger so payload-versus-commitment differences can be
explained offline.

`ExportCanonicalForm` defines the signed bytes as an explicit line-oriented format. The
earlier approach hashed a Jackson serialization, which is not independently reproducible:
a recipient would have to replicate one serializer's field ordering, null handling and
date format exactly. `ExportVerifier` implements the recipient side and touches no
database.

## Key management

`SigningKeyStore` abstracts the backend so a KMS/HSM, an injected secret and a durable
local file are interchangeable. Selection order is configured keys → file store →
explicit ephemeral, and startup fails if none is present. Signatures name their key id,
so rotation retires a key without invalidating evidence signed under it.
