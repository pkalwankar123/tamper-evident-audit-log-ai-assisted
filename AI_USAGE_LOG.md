# AI Usage Log

This file records honest AI-assisted development for the Tamper-Evident Audit Log Service submission.

2026-08-19 - Prompt - 

Generate a simple Java 21 Spring Boot Maven project as the initial prototype for a tamper-evident audit-log service.

At this stage, create only the basic project structure and application bootstrap required to build and start the application.

The application should:

Use Java 21 and Spring Boot.
Use Maven.
Have a clean, minimal project structure.
Build successfully with Maven.
Start successfully as a Spring Boot application.
Contain only the minimum application bootstrap code required for this initial prototype.

Response - Basic project is getting created.
Action - mvn clean install
         System Up and done the commit.


2026-08-19 - Prompt - Evaluate whether cryptographic hashing is an appropriate design decision for making the audit log tamper-evident. 
Compare hashing, cryptographic signatures, and hash chaining/Merkle-tree approaches. 
Explain which approach is most suitable for this audit-log service, why, and what security properties it provides. 
Do not implement the solution yet.

Response - Cryptographic hashing is an appropriate design decision for making an audit log tamper-evident, but hashing alone is not sufficient if the goal is to detect modification, deletion, insertion, or reordering of audit records.
1. Simple Cryptographic Hashing

Each audit record can be converted into a deterministic representation and hashed using a strong algorithm such as SHA-256.

2. Digital Signatures

A digital signature uses a private key to sign the audit data or its hash.
Anyone with the corresponding public key can verify that the signed data has not changed and that it was signed by the holder of the private key.

3. Hash Chaining

For an audit-log service, hash chaining is particularly useful.

Instead of hashing each record independently, each record includes the hash of the previous record:

H1 = SHA256(CanonicalRecord1)

H2 = SHA256(CanonicalRecord2 + H1)

H3 = SHA256(CanonicalRecord3 + H2)

Design action final - Recommended Design

For the initial audit-log prototype, the most appropriate design is:

Canonical JSON + SHA-256 hashing + hash chaining
Design final


2026-08-19 - Prompt - Based on the security analysis, define the tamper-evident audit-log design for this Spring Boot Java 21 project. 
Specify how Canonical JSON, cryptographic hashing, hash chaining, and verification should work together. 
Define the audit record structure, hash calculation process, chain-linking mechanism, and tamper-detection process

response - 
Defined the detailed tamper-evident audit-log design based on the previous security analysis. 
The design uses Canonical JSON + SHA-256 cryptographic hashing + hash chaining + verification. 
Each audit record contains a previousHash linking it to the previous record and a hash calculated from its canonical representation. The verification process recalculates hashes and validates chain links to detect modified, deleted, inserted, or reordered records. 
The design provides tamper evidence/detection, while recognizing that hash chaining alone does not prevent an attacker with unrestricted write access from rewriting the complete chain.

2026-08-19 - Prompt - The design should ensure that redaction does not weaken the integrity mechanism: the redacted representation must be the data that is canonicalized and included in the integrity hash. Clearly distinguish data confidentiality/privacy protection through redaction from tamper detection through hashing and hash chaining.

Response - 
Yes — that wording is correct and important. It makes the security boundary very clear:

Redaction protects confidentiality/privacy.
Canonical JSON + hashing + hash chaining provide tamper detection.
The redacted version is what gets canonicalized and hashed, so the integrity check applies to exactly what is stored.

2026-08-19 - Prompt - Add unit tests to verify the tamper-evident audit-log mechanism.

2026-08-20 - Prompt - Add authentication and authorization to the service. Update project accordingly, add proven test cases, and update README.md and docs/RISKS_AND_TRADEOFFS.md to reflect what is now implemented vs. what remains a gap.

Response - Implemented Spring Security with HTTP Basic authentication and role-based
authorization (ROLE_AUDIT_WRITER, ROLE_AUDIT_READER, ROLE_AUDIT_ADMIN), enforced
per-endpoint via a SecurityFilterChain. Redaction and export require ROLE_AUDIT_ADMIN
specifically (treated as high-impact/evidentiary actions), separate from read access.
In-memory users with dev-only default passwords, overridable via
AUDIT_SECURITY_*_PASSWORD environment variables, matching the existing pattern already
used for Ed25519 signing keys. Extended AuditLogIntegrationTest with dedicated
authentication tests (401 when unauthenticated) and authorization tests (403 with the
wrong role, 2xx with the correct role) for every endpoint, and updated the existing
functional tests to authenticate as admin so they stay focused on audit-log behavior
rather than security. Updated README.md (new Authentication & Authorization section,
curl examples now show -u credentials) and docs/RISKS_AND_TRADEOFFS.md (the "no
authentication or authorization" row now describes what is enforced and what is still a
gap - external IdP, MFA, secrets management, key rotation).

2026-08-20 - Prompt - Docs and Swagger were out of sync with the auth work: docs/TESTING.md
and docs/FINAL_ENGINEERING_SUMMARY.md still described "no authn/authz" as a boundary,
docs/ARCHITECTURE.md and docs/SCENARIOS.md never mentioned the security layer, and Swagger
UI had no "Authorize" button for the now-required HTTP Basic credentials. Update the docs
to accurately describe the current, implemented state and close the Swagger gap.

Response - Added a "Authentication & authorization" section to docs/ARCHITECTURE.md
describing SecurityConfig, the three-role model, and the stateless/CSRF-disabled rationale.
Updated docs/SCENARIOS.md (Scenario A and B) to note the auth boundary without changing the
functional scenario descriptions. Rewrote docs/TESTING.md to enumerate all 15 tests in
AuditLogIntegrationTest by name and intent (functional, unauthenticated/401, wrong-role/403,
correct-role, public docs) instead of the stale one-line "explicit security/product
boundary" note, and added the still-outstanding gaps (password hashing/brute-force/session
expiry not exercised, mvn verify not yet executed against the auth tests). Updated
docs/FINAL_ENGINEERING_SUMMARY.md's Design decisions, Validation, Assumptions, and
Limitations sections to reflect that authn/authz is now implemented rather than absent.
Added a Basic-auth SecurityScheme + description to OpenApiConfig so Swagger UI exposes an
Authorize button and documents which dev credentials to use, matching what SecurityConfig
actually enforces.
