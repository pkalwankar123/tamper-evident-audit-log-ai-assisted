# Scenario Execution

## Scenario A — Core service

Implemented: append-only write API, filtered/paginated query API, SHA-256 chain, and full verification endpoint. Integration tests create events, query them, verify success, mutate storage through the repository, and verify failure.

Every endpoint requires HTTP Basic authentication and role-based authorization
(`ROLE_AUDIT_WRITER`/`READER`/`ADMIN` - see `docs/ARCHITECTURE.md`). This does not change
the shape of the core API; it gates who may call it. Integration tests cover the
authentication (401 without credentials) and authorization (403 wrong role, 2xx correct
role) boundary for every endpoint - see `docs/TESTING.md`.

## Scenario B — Retention, redaction, export

Retention is soft archival. The verification walk includes both active and archived rows.

Structured redaction uses a second append-only integrity chain that records authorized payload transitions. The original payload commitment stays immutable in the primary chain; the active cleartext field is replaced with `[REDACTED]`. Direct changes not represented by the redaction ledger fail verification.

Bulk export supports exactly one of `actorId` or `resourceId`, includes intervening chain proof rows, and signs the manifest with Ed25519.

Both redaction and export are treated as high-impact, privacy-affecting / evidentiary
actions and require `ROLE_AUDIT_ADMIN`, not merely `ROLE_AUDIT_READER` - read access to a
record does not by itself grant authority to redact or export it.

## Scenario C — Compliance reporting

### Ambiguous statement

“Regulators need to be able to audit access to client account data.”

### Questions to resolve

- Which systems and data classifications count as client account data?
- What actions count as access: read, search result, export, print, API response, failed attempt?
- Which actor identities and delegated/service identities must be captured?
- What business purpose, consent, case/ticket, source application, device, and network context are required?
- What retention jurisdiction and legal hold rules apply?
- What report format, delivery SLA, timezone, and reviewer authorization are required?
- Are regulators allowed raw identifiers or only tokenized/pseudonymized values?

### Working requirement

Record every successful or denied attempt by a human or service identity to view, search, download, print, or transmit classified client-account data. Each event must identify the actor, subject account resource, action, decision, source system, purpose, correlation ID, and event time. Authorized compliance users must be able to filter by account, actor, action, decision, and time range and export a tamper-evident bundle. Sensitive payload fields must support approved redaction without concealing that a redaction occurred.

### Implemented slice

The generic audit event schema supports the normalized requirement using event types such as `CLIENT_DATA_ACCESSED`, `CLIENT_DATA_ACCESS_DENIED`, and `CLIENT_DATA_EXPORTED`. Query and export support actor/resource/time filtering. Purpose, decision, source system, and correlation ID are represented in structured payload.
