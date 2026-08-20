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
- **Auth:** HTTP Basic + three disjoint roles (`ROLE_AUDIT_WRITER`/`READER`/`ADMIN`) enforced
  per-endpoint via a Spring Security `SecurityFilterChain`. Redaction and export require
  `ROLE_AUDIT_ADMIN` specifically because they are high-impact (privacy-affecting /
  evidentiary) actions - read access does not imply authority to redact or export.

## Validation

- `mvn clean verify` (compile, Checkstyle, `AuditLogIntegrationTest`)
- Manual path: append → verify intact → API redact → verify intact → direct DB tamper → verify broken → export signed bundle
- Automated authn/authz boundary matrix: every role-guarded endpoint tested with no
  credentials (401), the wrong role (403), and the correct role (2xx) - see
  `docs/TESTING.md`
- **Note:** the auth-related test additions have been reviewed by manual trace against
  `SecurityFilterChain` matcher order and Spring Security's documented behavior, but
  `mvn clean verify` has not yet been executed against them in this environment (no local
  Maven/network access at the time of writing). Run it locally and confirm the Surefire
  summary before treating this as a validated result - see `AI_USAGE_LOG.md`.

## Assumptions

- Single-node writer is acceptable for the prototype.
- Caller may supply `timestamp`; server always sets immutable `ingestedAt`.
- Export recipients obtain the public key out of band.
- In-memory users with dev-only default passwords are acceptable for this exercise,
  overridable via `AUDIT_SECURITY_*_PASSWORD` env vars before running anywhere but a
  local machine.

## Limitations

Authentication and authorization are implemented (HTTP Basic + role-based access control),
which narrows but does not close the remaining gaps: no external IdP (OAuth2/OIDC), no MFA,
no centrally managed secrets (KMS/secrets manager), no rate limiting. Also: no KMS by
default for signing keys (ephemeral if unset), no multi-node sequencer, hash chain detects
ordinary tampering but not full privileged rewrite without external anchors. See
`docs/RISKS_AND_TRADEOFFS.md`.
