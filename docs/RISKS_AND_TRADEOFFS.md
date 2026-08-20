# Risks, Trade-offs, and Guardrails

| Risk | Current control | Production action |
|---|---|---|
| Privileged DB user rewrites an entire chain | Detects ordinary edits, not full recomputation | External signed checkpoints, WORM storage, restricted DB roles |
| Multi-node write race | JVM synchronization and tail row lock | Dedicated sequencer, advisory lock, or partitioned chains |
| Sensitive data remains in backups/logs | Active row is redacted | Backup lifecycle, crypto-shredding, log scrubbing |
| Ephemeral development signing key after restart | Configurable Ed25519 keys | KMS/HSM-backed persistent keys and rotation policy |
| Unauthenticated/unauthorized access to audit data and high-impact actions | HTTP Basic authentication + role-based authorization (`ROLE_AUDIT_WRITER`/`READER`/`ADMIN`) enforced per-endpoint via Spring Security `SecurityFilterChain`; redaction and export require `ROLE_AUDIT_ADMIN` specifically, not merely read access, since they are the privacy-impacting / evidentiary actions. Verified in `AuditLogIntegrationTest` (401 unauthenticated, 403 wrong role, 2xx correct role, for every endpoint) | Users are in-memory with dev-only default passwords (overridable via `AUDIT_SECURITY_*_PASSWORD` env vars) — this demonstrates enforcement boundaries, not production identity management. Replace with an external IdP (OAuth2/OIDC), short-lived tokens instead of static Basic credentials, MFA for admin actions, and centrally managed secrets (KMS/secrets manager) instead of env vars. No audit trail currently exists for authentication failures/authorization denials themselves — a real deployment should log those as audit events too |
| Full verification is O(n) | Correct and simple | Periodic signed checkpoints and incremental verification |
| Caller-supplied timestamps may be misleading | Immutable `ingestedAt` also stored | Permission controls and clock-skew policy |
| Hash delimiter ambiguity | Fixed ordered fields and constrained types | Length-prefix or canonical binary encoding |
| JPA schema auto-update | Fast local setup | Versioned Flyway/Liquibase migrations |

Human sign-off is required before changes to canonicalization, hash inputs, signing keys, redaction semantics, retention, or authorization because these can invalidate historical evidence or compliance guarantees.
