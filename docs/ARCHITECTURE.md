# Architecture Overview

## Components

- `AuditController`: HTTP boundary for append, query, verify, redact, and export.
- `AuditService`: append serialization, canonical hashing, filtering, redaction, archival, and verification.
- `ExportService`: builds a contiguous chain segment and signs its manifest.
- `RetentionService`: scheduled soft archival based on configurable age.
- `SecurityConfig`: HTTP Basic authentication and role-based authorization (see below).
- JPA repositories: H2 for local execution and PostgreSQL profile for realistic deployment.

## Authentication & authorization

Every `/audit/**` endpoint requires HTTP Basic credentials, enforced by a Spring Security
`SecurityFilterChain` (`SecurityConfig`) that matches on HTTP method and path before any
controller code runs. Three disjoint roles keep the boundary explicit:

| Role | Access |
|---|---|
| `ROLE_AUDIT_WRITER` | `POST /audit` only |
| `ROLE_AUDIT_READER` | `GET /audit`, `GET /audit/verify` |
| `ROLE_AUDIT_ADMIN` | Everything, including `POST /audit/{id}/redact` and `GET /audit/export` |

Redaction and export require `ROLE_AUDIT_ADMIN` specifically rather than falling back to
read access, because both produce privacy-affecting or evidentiary output - being able to
*view* a record does not imply authority to redact or export it. Roles are deliberately
kept disjoint (not hierarchical) so the authorization tests demonstrate real separation of
duties: `admin` is granted all three authorities explicitly, rather than reader/writer
being subsets implied by a role hierarchy.

Users are held in an `InMemoryUserDetailsManager` with BCrypt-hashed dev-only default
passwords, overridable via `AUDIT_SECURITY_WRITER_PASSWORD` / `_READER_PASSWORD` /
`_ADMIN_PASSWORD` environment variables - the same override pattern already used for the
Ed25519 signing keys. Sessions are stateless (`SessionCreationPolicy.STATELESS`, no cookie
is issued) and CSRF protection is disabled, since CSRF defends session/cookie-based flows
that do not apply to a per-request Basic-authenticated REST API. `/v3/api-docs/**` and
`/swagger-ui/**` remain public for local/demo convenience.

This authenticates and authorizes API access; it is not an identity platform. See
`docs/RISKS_AND_TRADEOFFS.md` for what is out of scope (external IdP, MFA, secrets
management, key rotation, auditing of auth failures themselves).

## Main-chain design

Each event stores `chainIndex`, immutable event fields, `payloadCommitment`, `previousHash`, and `recordHash`.

`payloadCommitment = SHA-256(canonical original payload JSON)`

`recordHash = SHA-256(chainIndex | event fields | timestamp | ingestedAt | payloadCommitment | previousHash)`

The genesis predecessor is 64 zeroes. JSON is serialized with ordered map keys before hashing. SHA-256 was selected for broad platform support and collision resistance. Hashing provides tamper evidence, not authentication; database controls and external anchors are still required.

## Redaction design

The visible `payload_json` may change only through the redaction API. The immutable main-chain record continues to commit to the original payload. Each redaction entry contains the record ID, JSON Pointer, reason, approving actor, prior payload hash, new payload hash, predecessor redaction-entry hash, and its own hash.

Verification checks:

1. The immutable main chain.
2. Every redaction transition and ledger link.
3. The current payload hash equals the latest approved redaction result.

This removes the sensitive cleartext from the active row while retaining evidence that the record originally committed to some value. It does not remove copies from backups, database logs, caches, or prior exports.

## Retention

Retention sets `archived=true`; it does not delete chain material. Normal queries exclude archived events unless `includeArchived=true`. Verification always includes them. A production archive tier could move rows while retaining ordered proof records or immutable checkpoints.

## Export

Exports contain the entire contiguous chain segment from the first to last matching event. Nonmatching records inside the segment are included as proof records with `selected=false`. The manifest hash is signed with Ed25519. Recipients verify the signature against a public key obtained from a trusted channel, then recompute the manifest and chain hashes.

## Data integrity and concurrency

The append path uses a JVM synchronized section and a pessimistic lock on the current tail. This is suitable for the single-node prototype. It is not sufficient for horizontally scaled writers; see the risk register.
