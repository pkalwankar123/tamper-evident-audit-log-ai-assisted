# Final Engineering Summary

## Plan / rationale

Build a tamper-evident audit log as an AI-assisted engineering exercise: normalize
requirements (including an ambiguous compliance statement), decompose into Scenarios
A/B/C, implement a runnable Spring Boot service, validate with executed tests, and
document design, risks and AI usage under human ownership.

## Artifacts

| Artifact | Location |
|---|---|
| Working service | `src/main/java/...`, `pom.xml`, `README.md` |
| Security design | `docs/SECURITY.md` |
| Architecture | `docs/ARCHITECTURE.md` |
| Scenarios A/B/C | `docs/SCENARIOS.md` |
| Risks / trade-offs | `docs/RISKS_AND_TRADEOFFS.md` |
| Testing approach | `docs/TESTING.md` |
| Executed test results | `TEST_EXECUTION_REPORT.md` |
| Retained evidence | `evidence/surefire/`, `evidence/jacoco/` |
| AI traceability | `AI_USAGE_LOG.md` |
| Attestation | `ATTESTATION.md` |

## Design decisions (high impact)

- **Identity is derived, never supplied.** `actorId` and `tenantId` were removed from the
  request models rather than validated at the boundary - a field a caller can populate is
  a field a caller can lie in, and validation only narrows the lie.
- **Authorization sits in the service layer**, not the controller, so it holds for any
  future caller and is testable without HTTP.
- **Chains are partitioned per tenant.** A tenant-scoped verification over a shared chain
  would report gaps for correct data.
- **Appends serialize on a database row lock**, advanced in the same transaction as the
  insert - so ordering holds across nodes and a failed append leaves no gap.
- **Signed checkpoints** anchor verification outside the data being verified, catching
  truncation and consistent rewrites that link checking cannot.
- **Signing keys must be durable.** No implicit ephemeral fallback; startup fails without
  a key source, because a key regenerated on boot silently invalidates all prior evidence.
- **Hash:** SHA-256 over ordered fields plus the payload commitment; genesis is 64 zero
  hex characters; timestamps truncated to milliseconds to match database precision.
- **Redaction:** a separate hash-linked ledger; the main chain keeps the original
  `payloadCommitment`.
- **Retention:** soft archive only; verification always includes archived rows; nothing
  deletes an audit record.
- **Export:** contiguous proof segment plus redaction ledgers, an explicitly defined
  canonical form, and an Ed25519-signed manifest verifiable offline.

## Validation

`mvn clean verify` - executed, **BUILD SUCCESS**: compile → Surefire → JaCoCo →
Checkstyle.

**156 tests, 0 failures, 0 errors, 0 skipped. 90.2 % line / 75.7 % branch coverage.**
Figures taken from `evidence/jacoco/jacoco.csv` and the retained Surefire XML, not from a
summary. Breakdown and scenario matrix: `TEST_EXECUTION_REPORT.md`.

Manual path also exercised end to end in tests: append → verify intact → redact → verify
intact → direct database tamper → verify broken → checkpoint → truncate → verify broken
on the checkpoint → export → verify the bundle offline.

## Assumptions

- Callers may supply an event `timestamp`; the server always sets an immutable,
  hashed `ingestedAt`.
- Export recipients obtain the trusted public key out of band. Verifying a bundle against
  its own embedded key proves internal consistency only.
- MFA and credential lifecycle belong to the identity provider; this service consumes
  tokens.

## Limitations

Named in full in `docs/SECURITY.md` and `docs/RISKS_AND_TRADEOFFS.md`. The material ones:
tests run against H2 rather than PostgreSQL; multi-node concurrency is not tested;
checkpoints and idempotency-key purging are not scheduled; there are no schema
migrations; rate limiting is per-node and in-memory; there is no token revocation; and
`FileSigningKeyStore` is a durable stand-in for a KMS, not an equivalent.
