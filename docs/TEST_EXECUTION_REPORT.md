# Test Execution & Coverage Report

## Status: executed

The Maven test/verification workflow has been executed and JaCoCo coverage has been
generated. The following values are taken from the JaCoCo coverage report produced by
the run.

## Command

```bash
mvn clean verify
```

This command runs compilation, Checkstyle, Surefire tests, and JaCoCo instrumentation/
report generation.

## Coverage result

| Metric | Missed | Total | Coverage |
|---|---:|---:|---:|
| Instructions | 561 | 5,483 | 89% |
| Branches | 83 | 346 | 76% |
| Complexity | 112 | 504 | 78% |
| Lines | 106 | 1,098 | 90% |
| Methods | 37 | 331 | 89% |
| Classes | 1 | 63 | 98% |

The rounded percentages above correspond to the JaCoCo report generated for
the current revision.

Coverage is considered together with the security, integration, validation,
authorization, integrity, and negative-path tests. Aggregate coverage alone
does not establish production readiness.

## Package Coverage

| Package | Instruction | Branch |
|---|---:|---:|
| `com.example.audit.service` | 88% | 74% |
| `com.example.audit.config` | 90% | 77% |
| `com.example.audit.security.keys` | 78% | 58% |
| `com.example.audit.util` | 59% | N/A |
| `com.example.audit.domain` | 94% | N/A |
| `com.example.audit.api` | 97% | 85% |
| `com.example.audit.security` | 98% | 84% |
| `com.example.audit` | 37% | N/A |

The highest-risk API and security packages have high executable coverage,
while lower coverage remains in selected utility, key-management, and
defensive branches.


**If your latest Maven run has a different test count, use that number instead of 173.**

---

## Update the security testing section

I recommend adding this because it directly supports the remediation you just implemented:

```markdown
## Security Test Coverage

The security test suite verifies the authentication and authorization
boundaries of the audit API.

Covered scenarios include:

- unauthenticated requests returning `401 Unauthorized`;
- authenticated writer access;
- authenticated reader access;
- authenticated administrator access;
- incorrect-role requests returning `403 Forbidden`;
- writer append authorization;
- reader query and verification authorization;
- administrator-only redaction;
- administrator-only export;
- API documentation access according to the active environment;
- authenticated actor identity propagation;
- tenant and ownership enforcement;
- request-size limits;
- rate limiting;
- replay/idempotency controls where enabled; and
- security-related validation and negative paths.

Development and test environments use isolated Basic authentication fixtures.
Production authentication is configured separately for OIDC/OAuth2 resource
server operation.

## Authenticated Actor Identity

Audit actor identity is derived from the authenticated security principal.

The API does not rely on a caller-supplied `actorId` as the authoritative
security identity.

For development and test authentication, the configured principals map to
tenant and actor identities, for example:

```properties
audit.identity.principals.writer.actor-id=advisor-17
audit.identity.principals.writer.tenant-id=tenant-a

audit.identity.principals.reader.actor-id=advisor-17
audit.identity.principals.reader.tenant-id=tenant-a

audit.identity.principals.admin.actor-id=admin-a
audit.identity.principals.admin.tenant-id=tenant-a


---

## Update the authentication section

Use this wording rather than saying JWT is required for development:

```markdown
## Authentication Model

The application supports environment-specific authentication.

### Development/Test

Development and test environments may use HTTP Basic authentication with
locally configured credentials.

These credentials are environment-specific test/development fixtures and are
not production credentials.

### Production

Production authentication is designed for OIDC/OAuth2 bearer-token validation.
The production configuration does not rely on fixed repository passwords or
development Basic-authentication credentials.

The authorization layer consumes the authenticated principal regardless of
which supported authentication mechanism established that principal.

## Export Testing

Export operations are restricted to authenticated administrators.

Export selection is evaluated within the authenticated tenant context.

Tests create audit records using the authenticated administrator identity and
then perform the export using the corresponding actor/resource selector.

The test does not rely on an arbitrary caller-supplied actor identity being
accepted as the authoritative security identity.