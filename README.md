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

## Authentication & Authorization

The API requires HTTP Basic credentials on every `/audit/**` endpoint except the public
API docs. Three roles enforce least privilege:

| Role | Can do | Dev username / password (override via env vars below) |
|---|---|---|
| `ROLE_AUDIT_WRITER` | `POST /audit` only | `writer` / `writer-dev-pass` |
| `ROLE_AUDIT_READER` | `GET /audit`, `GET /audit/verify` | `reader` / `reader-dev-pass` |
| `ROLE_AUDIT_ADMIN` | Everything, incl. `POST /audit/{id}/redact` and `GET /audit/export` | `admin` / `admin-dev-pass` |

Redaction and export are treated as **high-impact actions** (privacy-affecting /
evidentiary output) and require `ROLE_AUDIT_ADMIN` even though a reader can view the
same underlying data — read access does not imply authority to redact or export it.

Override the dev-only default passwords before running anywhere but your own machine:
```bash
export AUDIT_SECURITY_WRITER_PASSWORD='...'
export AUDIT_SECURITY_READER_PASSWORD='...'
export AUDIT_SECURITY_ADMIN_PASSWORD='...'
```

See `docs/RISKS_AND_TRADEOFFS.md` for what this does and does not cover (in-memory users,
no external IdP, no MFA — this demonstrates role-based enforcement, not production identity
management).

## API examples

```bash
# Append (writer or admin)
curl -s -X POST http://localhost:8080/audit \
  -u writer:writer-dev-pass \
  -H 'Content-Type: application/json' \
  -d '{
    "eventType":"CLIENT_DATA_ACCESSED",
    "actorId":"advisor-17",
    "resourceType":"ACCOUNT",
    "resourceId":"acct-100",
    "payload":{"accountNumber":"123456789","purpose":"support"}
  }'

# Query (reader or admin)
curl -s -u reader:reader-dev-pass 'http://localhost:8080/audit?actorId=advisor-17&resourceType=ACCOUNT&page=0&size=50'

# Verify chain (reader or admin)
curl -s -u reader:reader-dev-pass http://localhost:8080/audit/verify

# Redact (admin only - replace RECORD_UUID)
curl -s -X POST http://localhost:8080/audit/RECORD_UUID/redact \
  -u admin:admin-dev-pass \
  -H 'Content-Type: application/json' \
  -d '{"fieldPath":"/accountNumber","reason":"privacy request","actorId":"privacy-ops"}'

# Export (admin only - exactly one selector)
curl -s -u admin:admin-dev-pass 'http://localhost:8080/audit/export?actorId=advisor-17' > export.json

# Without credentials -> 401; with the wrong role -> 403
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/audit/verify              # 401
curl -s -o /dev/null -w '%{http_code}\n' -u writer:writer-dev-pass http://localhost:8080/audit/verify  # 403
```

## Validation demo

1. Create at least two events.
2. `GET /audit/verify` → `intact=true`.
3. Mutate a protected DB column directly.
4. `GET /audit/verify` → `intact=false` with violation type.
5. Use API redaction → verify again → `intact=true`.

Automated coverage: `AuditLogIntegrationTest` — append, query, verify, redact, tamper
detection, signed export, **plus role-based authentication/authorization**: every
endpoint tested unauthenticated (expect 401), with the wrong role (expect 403), and
with the correct role (expect success). See `docs/TESTING.md` for the full list.

## Production boundaries

Authentication and authorization are now implemented (HTTP Basic + role-based access
control — see above), which narrows but does not close this list. Still intentionally
out of scope for this prototype: an external identity provider (OAuth2/OIDC) in place of
in-memory users, MFA, centrally managed secrets (a KMS/secrets manager instead of
environment-variable overrides), rate limiting, TLS termination, immutable DB roles,
external timestamping, managed KMS for signing keys, key rotation, multi-node append
serialization, and WORM storage. See `docs/RISKS_AND_TRADEOFFS.md`.

## Repository guide

| Artifact | Purpose |
|---|---|
| `docs/ARCHITECTURE.md` | Design and integrity model |
| `docs/SCENARIOS.md` | Scenarios A, B, C (incl. compliance normalization) |
| `docs/TESTING.md` | Testing approach, gaps, trade-offs |
| `docs/TEST_EXECUTION_REPORT.md` | How to produce and store real Surefire/coverage output; current status |
| `docs/RISKS_AND_TRADEOFFS.md` | Threats and prototype limits |
| `docs/FINAL_ENGINEERING_SUMMARY.md` | Plan, artifacts, assumptions, limitations |
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
