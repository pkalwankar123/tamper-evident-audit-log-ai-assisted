# Architecture Overview

## Components

- `AuditController`: HTTP boundary for append, query, verify, redact, and export.
- `AuditService`: append serialization, canonical hashing, filtering, redaction, archival, and verification.
- `ExportService`: builds a contiguous chain segment and signs its manifest.
- `RetentionService`: scheduled soft archival based on configurable age.
- JPA repositories: H2 for local execution and PostgreSQL profile for realistic deployment.

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
