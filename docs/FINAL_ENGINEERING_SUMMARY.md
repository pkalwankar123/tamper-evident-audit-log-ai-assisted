# Final Engineering Summary

## Plan / rationale

Build a tamper-evident audit log as an AI-assisted engineering exercise: normalize requirements (including an ambiguous compliance statement), decompose into Scenarios A/B/C, implement a runnable Spring Boot prototype, validate with integration tests, and document design, risks, and AI usage under human ownership.

## Artifacts

| Artifact | Location |
|---|---|
| Working service | `src/main/java/...`, `pom.xml`, `README.md` |
| Architecture | `docs/ARCHITECTURE.md` |
| Scenarios A/B/C | `docs/SCENARIOS.md` |
| Risks / trade-offs | `docs/RISKS_AND_TRADEOFFS.md` |
| Testing approach | `docs/TESTING.md` |
| AI traceability | `AI_USAGE_LOG.md` |
| Attestation | `ATTESTATION.md` |

## Design decisions (high impact)

- **Hash:** SHA-256 over ordered fields + payload commitment; genesis = 64 zero hex chars.
- **Redaction:** separate ledger; keep original `payloadCommitment` on the main chain.
- **Retention:** soft archive (`archived=true`); verify always includes archived rows.
- **Export:** contiguous proof segment + Ed25519-signed manifest.
- **Timestamps in hash:** truncated to milliseconds to match DB Instant precision.

## Validation

- `mvn clean verify` (compile, Checkstyle, `AuditLogIntegrationTest`)
- Manual path: append → verify intact → API redact → verify intact → direct DB tamper → verify broken → export signed bundle

## Assumptions

- Single-node writer is acceptable for the prototype.
- Caller may supply `timestamp`; server always sets immutable `ingestedAt`.
- Export recipients obtain the public key out of band.

## Limitations

No authn/authz, no KMS by default, ephemeral signing keys if unset, no multi-node sequencer, hash chain detects ordinary tampering but not full privileged rewrite without external anchors. See `docs/RISKS_AND_TRADEOFFS.md`.
