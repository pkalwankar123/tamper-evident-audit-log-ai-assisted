# Testing Approach, Limitations, and Trade-offs

## What is covered

`mvn clean verify` runs compilation, Checkstyle, and Spring Boot integration tests against an isolated in-memory H2 database.

`AuditLogIntegrationTest` covers:

- append and generated chain metadata
- filtered query
- successful full-chain verification
- API redaction that keeps the chain intact
- unauthorized payload mutation detected by verify
- signed export with a contiguous proof segment

## What is not covered (and why)

| Gap | Why deferred |
|---|---|
| Multi-JVM concurrent writers | Prototype is single-node; cluster sequencer is out of scope |
| PostgreSQL Testcontainers | Optional profile exists; H2 proves API/integrity behavior locally |
| Cryptographic re-verify of export signature in test | Manifest fields asserted; offline verify is a reviewer manual step |
| Dedicated archive + verify regression | Soft-archive path exists; verify always includes archived rows by design |
| Authn/authz, rate limits, oversized payloads | Explicit security/product boundary for this exercise |

## Trade-off

Prefer end-to-end integrity tests that match the assignment’s validation story (write → query → verify → tamper → verify) over broad unit coverage of plumbing. Production would add concurrency, DB-parity, and security tests.
