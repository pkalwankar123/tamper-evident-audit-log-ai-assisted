# Tamper-Evident Audit Log Service

AI-assisted Spring Boot 3 / Java 21 prototype: append-only audit events, SHA-256 hash-chain verification, soft archival, structured redaction with a separate integrity ledger, and Ed25519-signed export bundles.

**Candidate:** Pradeep Kalwankar (`pradipkalwankar143@gmail.com`)  
**Attestation:** see `ATTESTATION.md`  
**AI process:** see `AI_USAGE_LOG.md`

## Quick start

Prerequisites: Java 21 and Maven 3.9+.

```bash
mvn clean verify
mvn spring-boot:run
```

### Swagger / OpenAPI

| URL | Purpose |
|-----|---------|
| http://localhost:8080/swagger-ui.html | Interactive API UI |
| http://localhost:8080/v3/api-docs | OpenAPI JSON |

Default profile uses file-backed H2 at `./data/auditdb`. PostgreSQL:

```bash
docker compose up -d postgres
SPRING_PROFILES_ACTIVE=postgres mvn spring-boot:run
```

## What was implemented

| Scenario | Coverage |
|---|---|
| A — Core | Append, filtered/paginated query, hash chain, verify |
| B — Extensions | Soft retention, structured redaction ledger, signed export |
| C — Ambiguity | Compliance statement normalized in `docs/SCENARIOS.md` |

## API examples

```bash
# Append
curl -s -X POST http://localhost:8080/audit \
  -H 'Content-Type: application/json' \
  -d '{
    "eventType":"CLIENT_DATA_ACCESSED",
    "actorId":"advisor-17",
    "resourceType":"ACCOUNT",
    "resourceId":"acct-100",
    "payload":{"accountNumber":"123456789","purpose":"support"}
  }'

# Query
curl -s 'http://localhost:8080/audit?actorId=advisor-17&resourceType=ACCOUNT&page=0&size=50'

# Verify chain
curl -s http://localhost:8080/audit/verify

# Redact (replace RECORD_UUID)
curl -s -X POST http://localhost:8080/audit/RECORD_UUID/redact \
  -H 'Content-Type: application/json' \
  -d '{"fieldPath":"/accountNumber","reason":"privacy request","actorId":"privacy-ops"}'

# Export (exactly one selector)
curl -s 'http://localhost:8080/audit/export?actorId=advisor-17' > export.json
```

## Validation demo

1. Create at least two events.
2. `GET /audit/verify` → `intact=true`.
3. Mutate a protected DB column directly.
4. `GET /audit/verify` → `intact=false` with violation type.
5. Use API redaction → verify again → `intact=true`.

Automated coverage: `AuditLogIntegrationTest` (append, query, verify, redact, tamper detection, signed export).

## Production boundaries

Prototype intentionally omits authentication/authorization, immutable DB roles, external timestamping, managed KMS, key rotation, multi-node append serialization, and WORM storage. See `docs/RISKS_AND_TRADEOFFS.md`.

## Repository guide

| Artifact | Purpose |
|---|---|
| `docs/ARCHITECTURE.md` | Design and integrity model |
| `docs/SCENARIOS.md` | Scenarios A, B, C (incl. compliance normalization) |
| `docs/TESTING.md` | Testing approach, gaps, trade-offs |
| `docs/RISKS_AND_TRADEOFFS.md` | Threats and prototype limits |
| `docs/FINAL_ENGINEERING_SUMMARY.md` | Plan, artifacts, assumptions, limitations |
| `SUBMISSION.md` | Submission checklist |
| `AI_USAGE_LOG.md` | AI transparency log |
| `ATTESTATION.md` | Personal attestation |

API contract: Swagger UI (`/swagger-ui.html`).

## Signing keys (optional for local demo)

Without configured keys the app generates an ephemeral Ed25519 pair (dev only):

```bash
./scripts/generate-ed25519-keys.sh
export AUDIT_SIGNING_PRIVATE_KEY_BASE64='...'
export AUDIT_SIGNING_PUBLIC_KEY_BASE64='...'
```

Pin the public key out of band; a key shipped only inside the export bundle is not a trust anchor by itself.
