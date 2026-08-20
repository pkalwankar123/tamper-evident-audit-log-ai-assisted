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

| Metric | Result |
|---|---:|
| Instruction coverage | **84%** |
| Branch coverage | **54%** |
| Missed instructions | 297 / 1,924 |
| Missed branches | 38 / 84 |
| Classes missed | 0 / 24 |
| Complexity missed / total | 48 / 153 |
| Lines missed / total | 51 / 350 |
| Methods missed / total | 13 / 111 |

### Interpretation

The project has **84% instruction coverage** and **54% branch coverage**.

The branch percentage is lower because branch coverage counts alternative decision
paths, including negative/error/security paths and framework-driven conditions. The
current tests intentionally emphasize the audit-log integrity story and the
authentication/authorization boundary rather than trying to maximize branch coverage.

## Test scope

The configured suite contains:

- `AuditLogIntegrationTest`: 2 tests
- `AuditSecurityTest`: 17 tests
- **Total configured tests: 19**

The functional tests cover the write -> query -> verify -> redact -> tamper-detect
flow and signed export behavior. The security tests cover unauthenticated access,
wrong-role access, successful role-based access, and public API documentation
endpoints.

## Generated JaCoCo artifacts

After a successful run, the generated reports are available under:

```text
target/site/jacoco/index.html
target/jacoco.exec
```

Surefire results are available under:

```text
target/surefire-reports/
```

`target/` should remain gitignored. Store a coverage snapshot in `docs/` only when
persistent evidence is required for a submission or review.

## Coverage policy

No minimum coverage percentage is currently enforced.

The project uses JaCoCo in **report-only mode**. This is intentional for the
prototype: coverage is used as evidence of test scope and gaps, not as an artificial
quality gate.

If a future requirement mandates a minimum, add a `jacoco:check` rule to `pom.xml`
and document the threshold and rationale.

## Important limitation

The coverage numbers above are the values shown by the supplied JaCoCo execution
report. The exact Surefire pass/fail/error/skipped counts should be taken from the
same run's console output or `target/surefire-reports/*.xml` if those values need to
be recorded separately.

## Recommended evidence

For a submission/review, keep:

1. `docs/TEST_EXECUTION_REPORT.md`
2. `docs/TESTING.md`
3. the generated `target/site/jacoco/index.html` report if persistent coverage
   evidence is required
4. Surefire XML/TXT results if individual test execution evidence is required
