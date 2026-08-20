# Testing Approach, Limitations, and Trade-offs

## What is covered

`mvn clean verify` runs compilation, Checkstyle, the test suite, and JaCoCo coverage
instrumentation against the isolated in-memory H2 database. Test coverage is split
across two classes by concern:

- **`AuditLogIntegrationTest`** (2 tests) - audit-log behavior, authenticated as
  `admin` so the assertions stay focused on the audit-log story rather than security.
- **`AuditSecurityTest`** (17 tests) - the authentication/authorization boundary
  matrix, kept separately so security coverage is independently reviewable.

The test suite has now been executed with Maven and JaCoCo coverage has been generated.
The reported coverage is recorded in `docs/TEST_EXECUTION_REPORT.md`.

## Audit-log behavior (`AuditLogIntegrationTest`)

- append and generated chain metadata (`appendQueryVerifyRedactAndDetectDirectTampering`)
- filtered query
- successful full-chain verification
- API redaction that keeps the chain intact
- unauthorized/direct payload mutation detected by verify
  (`intact=false`, `violationType=PAYLOAD_OR_REDACTION_LEDGER_MISMATCH`)
- signed export with a contiguous proof segment (`exportContainsSignedContiguousProofSegment`)

## Security (`AuditSecurityTest`) - authentication, no credentials (expect 401)

Every role-guarded endpoint, including redact:

- `appendWithoutCredentialsIsRejected` - `POST /audit`
- `queryWithoutCredentialsIsRejected` - `GET /audit`
- `verifyWithoutCredentialsIsRejected` - `GET /audit/verify`
- `redactWithoutCredentialsIsRejected` - `POST /audit/{id}/redact`
- `exportWithoutCredentialsIsRejected` - `GET /audit/export`

## Security (`AuditSecurityTest`) - authorization, wrong role (expect 403)

- `readerCannotAppend`
- `writerCannotQuery`
- `writerCannotVerify`
- `writerCannotRedact`
- `readerCannotRedact`
- `readerCannotExport`

## Security (`AuditSecurityTest`) - authorization, correct role succeeds

- `writerCanAppend`
- `readerCanQueryAndVerify`
- `adminCanRedact`
- `adminCanExport`

## Security (`AuditSecurityTest`) - public endpoints

- `apiDocsAreAccessibleWithoutCredentials`
- `swaggerUiIsAccessibleWithoutCredentials`

## Coverage interpretation

The executed JaCoCo report shows **84% instruction coverage** and **54% branch
coverage** across the project. This is acceptable for the prototype because the tests
prioritize the assignment's core security and integrity behavior rather than maximizing
coverage of every framework/plumbing branch.