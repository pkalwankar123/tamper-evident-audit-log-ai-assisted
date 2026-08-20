# Tamper-Evident Audit Log Service

Spring Boot 3 / Java 21 service for append-only audit events: per-tenant SHA-256 hash
chains, signed checkpoints, structured redaction with a separate integrity ledger, a
retention/archive lifecycle, and Ed25519-signed export bundles that a recipient can
verify offline.

**Candidate:** Pradeep Kalwankar
**Attestation:** `ATTESTATION.md` · **AI process:** `AI_USAGE_LOG.md`
**Security design:** `docs/SECURITY.md` · **Test results:** `TEST_EXECUTION_REPORT.md`

## Quick start

Prerequisites: Java 21, Maven 3.6+.

```bash
mvn clean verify                                    # 173 tests, JaCoCo + Checkstyle
mvn spring-boot:run -Dspring-boot.run.profiles=dev  # local run
```

The `dev` profile is required for a local run. Without a profile the service starts with
**no identity bindings and no signing key source**, so it refuses every request and
fails closed on startup - that is deliberate, not a bug. An unconfigured deployment
should not guess who the caller is.

On first `dev` start the console prints a randomly generated password for each of the
three local users:

```
No password configured for local Basic-auth user 'writer'.
Generated for this run only: 6f2c...
```

Pin them if you prefer:

```bash
export AUDIT_SECURITY_WRITER_PASSWORD='...'
export AUDIT_SECURITY_READER_PASSWORD='...'
export AUDIT_SECURITY_ADMIN_PASSWORD='...'
```

There are no default passwords anywhere in this repository.

### PostgreSQL

```bash
export AUDIT_DB_NAME=audit AUDIT_DB_USERNAME=audit AUDIT_DB_PASSWORD='choose-one'
docker compose up -d postgres
export DB_URL=jdbc:postgresql://localhost:5432/audit DB_USERNAME=audit DB_PASSWORD="$AUDIT_DB_PASSWORD"
mvn spring-boot:run -Dspring-boot.run.profiles=dev,postgres
```

### API docs

Reachable without credentials **only** in the `dev` profile with Basic auth enabled:
http://localhost:8080/swagger-ui.html · http://localhost:8080/v3/api-docs
Disabled entirely under `prod`, and not public when OIDC is enabled.

## Identity model

Callers never supply an actor or tenant. Both are derived from the authenticated
principal, and the request bodies have no field for them.

| Mechanism | actorId | tenantId | roles |
|---|---|---|---|
| OIDC / JWT (production) | `sub` claim | `tenant_id` claim | `roles` claim + scopes |
| HTTP Basic (dev/test only) | `audit.identity.principals.<user>.actor-id` | `...tenant-id` | user authorities |

Authorization has two axes, enforced in the **service layer** rather than only at the
controller:

- **Tenant** is absolute - nobody, administrators included, crosses it.
- **Actor** applies within a tenant - an admin acts across actors, others only as
  themselves.

| Role | May do |
|---|---|
| `ROLE_AUDIT_WRITER` | `POST /audit`, always stamped with its own derived actor |
| `ROLE_AUDIT_READER` | `GET /audit`, `GET /audit/{id}`, `GET /audit/verify` - own actor only |
| `ROLE_AUDIT_ADMIN` | The above across its tenant, plus redact, export, archive, retention and checkpoints |

Redaction, export, archive, retention and checkpoints are high-impact
(privacy-affecting, evidentiary, operational) and require `ROLE_AUDIT_ADMIN`
specifically - read access does not imply authority to perform them.

## Endpoints

| Method | Path | Role | Notes |
|---|---|---|---|
| `POST` | `/audit` | writer | Optional `Idempotency-Key` header; replay returns `200` + `Idempotent-Replay: true` |
| `GET` | `/audit` | reader/admin | Filter, paginate; tenant-scoped, actor-scoped for non-admins |
| `GET` | `/audit/{id}` | reader/admin | 403 across a tenant or actor boundary |
| `GET` | `/audit/verify` | reader/admin | Chain + redaction ledger + signed checkpoints |
| `POST` | `/audit/{id}/redact` | admin | JSON Pointer field path |
| `GET` | `/audit/export` | admin | Exactly one of `actorId` / `resourceId` |
| `POST` | `/audit/archive` | admin | `olderThanDays`; reports `chainStillIntact` |
| `POST` | `/audit/retention/run` | admin | Applies `audit.retention.days` |
| `POST` `GET` | `/audit/checkpoints` | admin | Create / list signed checkpoints |

## API examples

```bash
AUTH='writer:<generated-password>'

# Append. Note the absence of actorId/tenantId - they are derived, not sent.
curl -su "$AUTH" -X POST http://localhost:8080/audit \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: 8f14e45f-ceea-467a-9f8c-1a2b3c4d5e6f' \
  -d '{"eventType":"CLIENT_DATA_ACCESSED","resourceType":"ACCOUNT",
       "resourceId":"acct-100","payload":{"accountNumber":"123456789","purpose":"support"}}'

# Verify the calling tenant's chain
curl -su 'reader:<pw>' http://localhost:8080/audit/verify

# Redact (admin); the redacting actor is taken from the principal
curl -su 'admin:<pw>' -X POST http://localhost:8080/audit/<id>/redact \
  -H 'Content-Type: application/json' \
  -d '{"fieldPath":"/accountNumber","reason":"privacy request"}'

# Signed checkpoint, then a verifiable export bundle
curl -su 'admin:<pw>' -X POST http://localhost:8080/audit/checkpoints
curl -su 'admin:<pw>' 'http://localhost:8080/audit/export?actorId=advisor-17' > bundle.json
```

`bundle.json` is verifiable offline with `ExportVerifier` - it re-derives every record
hash, the links between them, each payload against its commitment via the exported
redaction ledger, the manifest hash, and the Ed25519 signature, without touching the
database.

## How integrity works

Each record stores `previousHash` and `recordHash` over its immutable fields. Chains are
**per tenant**, because a tenant-scoped verification over a shared chain would see a gap
wherever another tenant's records were filtered out.

Appends serialize on a `PESSIMISTIC_WRITE` lock on the tenant's `chain_heads` row, and
the head advances in the same transaction as the insert - so concurrent writers are
ordered by the database (which every node shares), and a failed append consumes no index
and leaves no gap.

Link checking alone cannot detect a *consistent* rewrite: delete the last three records
and the remainder still links perfectly. **Signed checkpoints** close that hole by
committing to `(chainIndex, recordHash)` outside the data being verified. Verification
reports `CHECKPOINT_MISSING_RECORDS`, `CHECKPOINT_MISMATCH` or
`CHECKPOINT_SIGNATURE_INVALID` accordingly.

Redaction rewrites the payload and appends a hash-linked ledger entry; verification
replays the ledger, so an authorized redaction verifies and an unexplained payload
change does not.

## Retention

Two states: active, then archived once older than `audit.retention.days`. Archiving sets
a flag on a field no hash covers, so archived records still verify and still export.
**Nothing deletes an audit record** - hard deletion would break the chain by
construction and is not offered.

## Production

Activate with `--spring.profiles.active=prod`. Two independent mechanisms keep it fail
closed: every `${VAR}` has no default, and `ProductionSecurityValidator` aborts startup -
listing all problems at once - if OIDC is off, Basic auth is on, signing keys are
ephemeral or absent, TLS is unaccounted for, CORS is `*`, H2/Swagger/API-docs are
exposed, `ddl-auto` is not `none`/`validate`, or the datasource is H2.

Required environment: `AUDIT_DB_URL`, `AUDIT_DB_USERNAME`, `AUDIT_DB_PASSWORD`,
`AUDIT_OIDC_ISSUER_URI`, `AUDIT_OIDC_AUDIENCE`, `AUDIT_SIGNING_KEY_ID`,
`AUDIT_SIGNING_PRIVATE_KEY_BASE64`, `AUDIT_SIGNING_PUBLIC_KEY_BASE64`,
`AUDIT_TLS_ENABLED`, `AUDIT_TLS_EXTERNALLY_TERMINATED`.

MFA is intentionally not implemented here - it is an authentication-time concern owned
by the identity provider, and this service consumes the resulting token.

## Configuration layout

| File | Purpose |
|---|---|
| `application.properties` | Shared, non-secret settings. No credentials, no bindings, no defaults standing in for one. |
| `application-dev.properties` | Local development. Generated passwords, file-backed signing keys, dev identity bindings. |
| `application-prod.properties` | Production. No fallbacks; validated at startup. |
| `application-postgres.properties` | PostgreSQL datasource; no credential defaults. |
| `src/test/resources/application.properties` | Test fixtures against an in-memory database. |

## Tests and evidence

`mvn clean verify`: **173 tests, 0 failures, 0 errors, 0 skipped**; JaCoCo reports
**89.0 % line / 76.0 % branch** coverage. Reports are retained in `evidence/` rather
than only in `target/`, so the numbers above can be checked without re-running the
build. Full breakdown and the scenario matrix: `TEST_EXECUTION_REPORT.md`.

## Documentation

| Document | Contents |
|---|---|
| `docs/SECURITY.md` | Control-by-control design, what proves each, and known limitations |
| `TEST_EXECUTION_REPORT.md` | Actual counts, actual coverage, scenario matrix, evidence paths |
| `docs/ARCHITECTURE.md` | Components and data model |
| `docs/RISKS_AND_TRADEOFFS.md` | Risk register with current control and production action |
| `docs/TESTING.md` | Testing approach and what is deliberately not covered |
| `docs/SCENARIOS.md` | Assignment scenarios and the ambiguity resolution |
