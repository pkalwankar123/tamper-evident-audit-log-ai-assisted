# Testing Approach, Limitations, and Trade-offs

Actual test counts and coverage are generated from the retained Surefire and
JaCoCo reports in `evidence/`. This document explains the testing approach,
current results, deliberate testing choices, and remaining coverage boundaries.

## Current Result

The current revision was verified using:

```bash
mvn clean verify

## Structure

Thirteen classes, each with one job, so a failure identifies the broken rule rather than
whichever scenario happened to touch it.

| Class | Tests | Focus |
|---|---:|---|
| `AuditLogIntegrationTest` | 30 | End-to-end story, authentication, role boundaries, tampering, idempotency over HTTP |
| `MalformedRequestTest` | 24 | Validation, malformed input, boundaries, size limits |
| `ServiceLayerAuthorizationTest` | 18 | Ownership and tenant isolation driven directly at the services |
| `ProductionSecurityValidatorTest` | 13 | Every fail-closed production rule |
| `AuditAccessPolicyTest` | 11 | Authorization rules and identity derivation as pure units |
| `ExportVerificationTest` | 11 | Export cardinality and genuine offline verification |
| `SigningKeyStoreTest` | 10 | Key persistence across restart, rotation, fail-closed startup |
| `OidcAuthenticationTest` | 10 | JWT chain, claim-to-identity mapping, role mapping |
| `TenantIsolationHttpTest` | 8 | Cross-tenant denial over the real HTTP stack |
| `RetentionAndArchiveTest` | 8 | Retention lifecycle, archive authorization, integrity preservation |
| `CheckpointIntegrityTest` | 6 | Truncation and rewrite detection |
| `AppendConcurrencyAndRollbackTest` | 4 | Concurrent appends, rollback, idempotency races |
| `RateLimitFilterTest` | 3 | Rate limiting with its own low ceiling |

## Deliberate choices

**Authorization is tested twice, at two levels.** `ServiceLayerAuthorizationTest` drives
`AuditService` / `ExportService` / `CheckpointService` directly with constructed
`AuthenticatedActor` values, no HTTP. Controller tests only prove that *this* controller
enforces the rules; service-layer tests prove the guarantee survives a future caller
that is not this controller.

**Cross-tenant scenarios use JWT principals.** The suite needs a second tenant, and
minting one as a token claim exercises the production mechanism rather than inventing a
second set of local Basic users that would only have tested the fixture.

**Tamper tests go around JPA where they must.** The chain-link columns are mapped
`updatable = false`, so Hibernate will not write them - which is the point. The reorder
test issues direct SQL, because that is what an attacker with database access does.

**Every negative test asserts state, not just status.** A 400 that still appended a
record would be worse than a 500, so the malformed-input tests check the record count as
well as the response code.

**Export verification works from the exported JSON.** Bundles are pulled over HTTP,
deserialized, and handed to `ExportVerifier`, which consults no database. A test
asserting only that `manifestHash` and `signatureBase64` are non-empty would pass
against a bundle whose contents had been swapped wholesale - the earlier version of this
suite did exactly that and called it covered.

**Isolation by truncation, not by context rebuild.** `AbstractAuditTest` clears the
tables before each test. Rebuilding the Spring context per method costs seconds each;
across 100+ integration tests that is the difference between a suite people run and one
they skip. `RateLimitFilterTest` is the exception - its limiter holds in-memory
per-principal counters, so it does rebuild between methods.

## What the suite caught

Both of these looked correct and were not, which is the argument for the tests:

1. **Idempotency was inert.** The request fingerprint included the server-assigned
   timestamp, so a genuine retry never matched and was answered `409`. Replay protection
   existed and protected nothing.
2. **Concurrent first-appends failed 7 of 8 times.** The chain-head row was created in a
   `REQUIRES_NEW` transaction that also swallowed the duplicate-key exception, leaving
   the transaction rollback-only and throwing at commit.

## What is not covered, and why

| Gap | Why |
|---|---|
| PostgreSQL via Testcontainers | Tests run on H2 in PostgreSQL mode. Row-lock and constraint semantics are close but not identical, and the append serialization is exactly the kind of thing that can differ. This is the most valuable missing test. |
| Multi-JVM / multi-node concurrency | The mechanism under test - a database row lock - is what would serialize separate nodes, but only single-JVM concurrency has been demonstrated. |
| Process crash mid-append | Durability rests on ordinary transactional guarantees, assumed rather than demonstrated. |
| A live identity provider | Token decoding is stubbed by Spring Security's test support. The issuer, audience and expiry validators are wired but not proven against a real JWKS endpoint. |
| Automatic checkpoint scheduling | Checkpoints are created on demand. Nothing schedules them, so the truncation-detection window is as wide as the gap between manual checkpoints - tested, but not automated. |
| Fuzzing / exhaustive abuse matrix | A representative set is covered (oversized payload and header, malformed JSON, bad encodings in paths, invalid pagination and timestamps). Systematic fuzzing was not attempted. |
| TLS termination | The production validator asserts TLS is *accounted for*; no test terminates a real TLS connection. |
| Redaction of array elements | Only object-field JSON Pointers are supported, and only that is tested - the limitation is enforced, not silently broken. |
| Rate limiter behaviour across a window boundary | The fixed window reset is not tested; doing so would need clock control the filter does not currently expose. |

## Branch coverage

76.0 % is the weakest metric and is stated rather than rounded away. The uncovered
branches are concentrated in defensive null/blank guards and in error paths that need a
failing filesystem or database to reach - for example the POSIX-permission fallback in
`FileSigningKeyStore`, which is skipped on Windows, and the `NoSuchAlgorithmException`
branch in `Hashing`, which a conformant JRE cannot enter.

## Evidence

`target/` is gitignored; the reports are copied to `evidence/` and committed:

- `evidence/surefire/TEST-*.xml` and `*.txt` - 13 classes
- `evidence/jacoco/jacoco.xml`, `jacoco.csv`, `index.html`

No percentage in this repository is quoted from anywhere other than
`evidence/jacoco/jacoco.csv`.
