# Risks, Trade-offs, and Guardrails

| Risk | Current control | Production action |
|---|---|---|
| Privileged DB user rewrites an entire chain | Detects ordinary edits, not full recomputation | External signed checkpoints, WORM storage, restricted DB roles |
| Multi-node write race | JVM synchronization and tail row lock | Dedicated sequencer, advisory lock, or partitioned chains |
| Sensitive data remains in backups/logs | Active row is redacted | Backup lifecycle, crypto-shredding, log scrubbing |
| Ephemeral development signing key after restart | Configurable Ed25519 keys | KMS/HSM-backed persistent keys and rotation policy |
| No authentication or authorization | Explicit prototype boundary | OAuth2/mTLS, RBAC/ABAC, separation of duties |
| Full verification is O(n) | Correct and simple | Periodic signed checkpoints and incremental verification |
| Caller-supplied timestamps may be misleading | Immutable `ingestedAt` also stored | Permission controls and clock-skew policy |
| Hash delimiter ambiguity | Fixed ordered fields and constrained types | Length-prefix or canonical binary encoding |
| JPA schema auto-update | Fast local setup | Versioned Flyway/Liquibase migrations |

Human sign-off is required before changes to canonicalization, hash inputs, signing keys, redaction semantics, retention, or authorization because these can invalidate historical evidence or compliance guarantees.
