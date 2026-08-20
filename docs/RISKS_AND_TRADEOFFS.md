# Risks, Trade-offs, and Guardrails

Current control, and what production would still need. Where a control is claimed, the
test that proves it is named; where something is not implemented, it says so.

## Identity and authorization

| Risk | Current control | Production action |
|---|---|---|
| Caller-supplied `actorId` lets any writer impersonate any actor | **Fixed by removal.** The field no longer exists on the request. `ActorResolver` derives actor and tenant from token claims or the principal binding table. Proven by `ServiceLayerAuthorizationTest`, `AuditAccessPolicyTest`, `OidcAuthenticationTest` | None outstanding for this control; keep the claim names aligned with the IdP |
| Query, verify, export or archive leaking another actor's data | `AuditAccessPolicy` enforced in the service layer, not the controller. Non-admins pinned to their own actor; explicit requests for another are denied rather than rewritten. Proven by 18 service-layer tests | A many-actors-per-user model (a team lead over several advisors) would need a group/scope concept; today the mapping is one actor per principal |
| Cross-tenant access, including by administrators | Tenant is an absolute predicate on every read and write, and chains are partitioned per tenant. Proven by `TenantIsolationHttpTest`, `ServiceLayerAuthorizationTest` | Consider row-level security in the database as defence in depth, so a bug in application code cannot cross the boundary either |
| A principal with no configured identity | Denied outright - no default tenant, no unrestricted principal. Proven by `AuditAccessPolicyTest.unboundPrincipalIsDenied` | — |

## Authentication and secrets

| Risk | Current control | Production action |
|---|---|---|
| Default or demo credentials reaching a real deployment | **No credential exists in the repository.** Base config has none; dev generates a random password per run and logs it; prod refuses Basic auth entirely. Proven by `ProductionSecurityValidatorTest` | Secrets from a managed store rather than environment variables; rotation without restart |
| Static Basic credentials with no expiry or revocation | Production uses OIDC/OAuth2 bearer tokens with issuer, audience and expiry validation. MFA belongs to the IdP by design | **Token revocation is not implemented** - tokens are valid until expiry. Introspection or a deny list would be needed |
| Ephemeral signing key silently invalidating all prior evidence | **Fixed.** No implicit ephemeral fallback; startup fails without a durable key source. `SigningKeyStore` abstracts KMS/file/ephemeral. Proven by `SigningKeyStoreTest` | Real KMS/HSM behind the same interface; `FileSigningKeyStore` keeps the private key on local disk and is a stand-in, not an equivalent |
| Key rotation invalidating historical evidence | Every signature names its key id; retired keys stay resolvable. Proven by `SigningKeyStoreTest.rotationRetainsEarlierKeysForVerification` | A rotation schedule and a published key directory so external verifiers can resolve retired keys too |
| Insecure production configuration starting anyway | `ProductionSecurityValidator` checks eleven conditions at startup and aborts listing all failures. Unresolvable placeholders are the second, independent mechanism | Extend to a deployment-time policy check as well, so failures surface before rollout rather than at boot |
| H2 or Swagger exposed in production | Both rejected by the validator; the API-docs matcher is only registered when Basic auth is active and OIDC is off | — |
| TLS silently absent | The validator requires either `server.ssl.enabled` with a keystore or an explicit `externally-terminated=true` declaration | mTLS between the proxy and the service if the network is not trusted |

## Integrity

| Risk | Current control | Production action |
|---|---|---|
| Multi-node write race corrupting the chain | **Fixed.** `PESSIMISTIC_WRITE` row lock on the per-tenant `chain_heads` row, held for the append transaction - the database orders writers across nodes. Replaced an in-process `synchronized` that did nothing across nodes *and* released before commit. Proven by `AppendConcurrencyAndRollbackTest` | Verify under real PostgreSQL and under genuine multi-node load; a high-write deployment may need per-tenant sharding to avoid head contention |
| A failed append burning a chain index and leaving a permanent gap | The head advances in the same transaction as the insert, so a rollback restores it. Proven by `failedAppendConsumesNoIndex` | — |
| Privileged database user rewriting the chain consistently | **Signed checkpoints.** Truncation and wholesale rewrites are detected against a commitment external to the data. Proven by `CheckpointIntegrityTest` | Checkpoints are created on demand only - **nothing schedules them**, so the detection window is the gap between manual checkpoints. Schedule them, and anchor them externally (WORM storage, a notary, or a second system) so an attacker with full database access cannot delete the checkpoints too |
| Unauthorized modification, deletion or reordering | Detected as `PAYLOAD_OR_REDACTION_LEDGER_MISMATCH`, `CHAIN_INDEX_GAP`, `PREVIOUS_HASH_MISMATCH`, `RECORD_HASH_MISMATCH`. Proven by `AuditLogIntegrationTest` | Restricted database roles so the application user cannot `UPDATE` or `DELETE` audit rows at all |
| Verification is O(n) | Correct and simple at prototype scale | Incremental verification resuming from the most recent checkpoint |
| Hash delimiter ambiguity | Fixed field order and constrained column lengths | Length-prefixed or canonical binary encoding |
| Caller-supplied timestamps misleading a reader | An immutable server-side `ingestedAt` is stored and hashed alongside | Clock-skew policy and a bound on how far a supplied timestamp may deviate |

## API surface

| Risk | Current control | Production action |
|---|---|---|
| Replay / duplicate submission | Durable `Idempotency-Key` support in the database, tenant-scoped; replay returns the original, key reuse with a different body is `409`. Proven by `AuditLogIntegrationTest`, `AppendConcurrencyAndRollbackTest` | Expiry is configured (`retention-hours`) but **the purge is not scheduled** - `purgeExpiredIdempotencyKeys` exists and is not yet wired to a job |
| Abuse / flooding | Per-principal fixed-window limiter positioned after authentication. Proven by `RateLimitFilterTest` | **In-memory and per-node**: resets on restart, not shared across a cluster. Move to Redis or an ingress limiter |
| Oversized payloads | Rejected on declared `Content-Length` before parsing (413), with the service-layer check authoritative, plus container-level caps | Enforce a body limit at the ingress as well |
| Pagination abuse | Strict bounds, rejected rather than clamped | — |
| CSRF | Explicitly disabled for a stateless, cookie-less API; `audit.security.csrf-enabled` re-enables it | Must be re-enabled if a cookie/session browser flow is ever put in front |
| CORS misconfiguration | Deny by default, never wildcard, never `allowCredentials`; `*` rejected in production | Keep the allow-list as narrow as the real set of browser callers |
| Error responses leaking existence | Authorization denials return a fixed message; internal detail is not returned | — |

## Data lifecycle

| Risk | Current control | Production action |
|---|---|---|
| Retention deleting evidence | Archiving is a flag on a non-hashed field; **nothing deletes an audit record**. Archived records still verify and still export. Proven by `RetentionAndArchiveTest` | Legal-hold support, so a record under hold is exempt from archival |
| Sensitive data surviving in backups and logs | The active row is redacted through the ledger | Backup lifecycle policy, crypto-shredding, log scrubbing - none of which this service can do alone |
| Redaction limited to object fields | Array-element pointers are rejected explicitly rather than silently mishandled | Extend the pointer handling if array redaction is required |
| Schema drift | Production requires `ddl-auto=validate` | **No Flyway/Liquibase migrations are provided** - the schema must currently be created out of band |

## Sign-off

Human sign-off is required before changing canonicalization, hash inputs, signing keys,
redaction semantics, retention, identity derivation or authorization. Each can
invalidate historical evidence, compliance guarantees, or access-control correctness in
ways that do not show up as a failing build.

## On coverage numbers

Earlier revisions of this project referenced coverage percentages with no report to
substantiate them. Every number quoted now comes from `evidence/jacoco/jacoco.csv`,
produced by the run recorded in `TEST_EXECUTION_REPORT.md` and committed alongside the
code.
