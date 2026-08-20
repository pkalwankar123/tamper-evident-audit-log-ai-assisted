package com.example.audit;

import com.example.audit.api.ApiModels;
import com.example.audit.security.keys.SigningKey;
import com.example.audit.service.ExportCanonicalForm;
import com.example.audit.service.ExportVerifier;
import com.example.audit.util.Hashing;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Export correctness and - the part that was previously only claimed - actual
 * independent verification.
 *
 * <p>Every test here works from the exported JSON as a recipient would: the bundle is
 * pulled over HTTP, deserialized, and handed to {@link ExportVerifier}, which re-derives
 * every hash and checks the Ed25519 signature without consulting the database. A test
 * that asserted only that {@code manifestHash} and {@code signatureBase64} were
 * non-empty would pass against a bundle whose contents had been swapped wholesale.
 */
class ExportVerificationTest extends AbstractAuditTest {

    @Autowired ExportVerifier verifier;

    private ApiModels.ExportManifest exportFor(String actorId) throws Exception {
        String json = mvc.perform(get("/audit/export").with(asAdmin()).param("actorId", actorId))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return mapper.readValue(json, ApiModels.ExportManifest.class);
    }

    private void appendAs(org.springframework.test.web.servlet.request.RequestPostProcessor who,
                          String eventType, String resourceId) throws Exception {
        mvc.perform(post("/audit").with(who).contentType(MediaType.APPLICATION_JSON)
                        .content(eventBody(eventType, resourceId)))
                .andExpect(status().isCreated());
    }

    @Test
    @DisplayName("the bundle spans the contiguous segment: exactly 3 records, exactly 2 selected")
    void exportSpansContiguousSegmentWithExactCardinality() throws Exception {
        appendAs(asWriter(), "A", "resource-1");   // advisor-17, index 1
        appendAs(asAdmin(), "B", "resource-2");    // admin-a,    index 2
        appendAs(asWriter(), "C", "resource-3");   // advisor-17, index 3

        ApiModels.ExportManifest manifest = exportFor(ADVISOR_17);

        // Three records, because indices 1..3 are needed to check the hash links between
        // the two selected ones; the middle record belongs to another actor and is
        // present as context only.
        assertThat(manifest.records()).hasSize(3);
        assertThat(manifest.records().stream().filter(ApiModels.ExportRecord::selected)).hasSize(2);
        assertThat(manifest.records().stream()
                .filter(ApiModels.ExportRecord::selected)
                .map(record -> record.event().actorId()))
                .containsOnly(ADVISOR_17);
        assertThat(manifest.records().get(1).selected()).isFalse();
        assertThat(manifest.records().get(1).event().actorId()).isEqualTo("admin-a");
        assertThat(manifest.records().stream().map(record -> record.event().chainIndex()))
                .containsExactly(1L, 2L, 3L);
        assertThat(manifest.tenantId()).isEqualTo(TENANT_A);
    }

    @Test
    @DisplayName("an untouched bundle verifies independently from its own contents")
    void untouchedBundleVerifies() throws Exception {
        appendAs(asWriter(), "A", "resource-1");
        appendAs(asWriter(), "B", "resource-2");

        ExportVerifier.Result result = verifier.verify(exportFor(ADVISOR_17));

        assertThat(result.problems()).isEmpty();
        assertThat(result.valid()).isTrue();
    }

    @Test
    @DisplayName("a bundle containing a redacted record still verifies, via its exported ledger")
    void redactedRecordVerifiesThroughItsLedger() throws Exception {
        String created = mvc.perform(post("/audit").with(asAdmin()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"eventType\":\"X\",\"resourceType\":\"ACCOUNT\",\"resourceId\":\"r-1\","
                                + "\"payload\":{\"ssn\":\"123-45-6789\",\"note\":\"keep\"}}"))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        String id = mapper.readTree(created).get("id").asText();

        mvc.perform(post("/audit/{id}/redact", id).with(asAdmin()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fieldPath\":\"/ssn\",\"reason\":\"privacy request\"}"))
                .andExpect(status().isOk());

        ApiModels.ExportManifest manifest = exportFor("admin-a");

        // The payload no longer hashes to its original commitment; the ledger in the
        // bundle is what explains the difference, and it is checked rather than trusted.
        assertThat(manifest.records().get(0).redactions()).hasSize(1);
        assertThat(manifest.records().get(0).redactions().get(0).actorId()).isEqualTo("admin-a");
        assertThat(verifier.verify(manifest).problems()).isEmpty();
    }

    @Test
    @DisplayName("altering a payload inside the bundle is detected")
    void alteredPayloadInBundleIsDetected() throws Exception {
        appendAs(asWriter(), "A", "resource-1");
        String json = mvc.perform(get("/audit/export").with(asAdmin()).param("actorId", ADVISOR_17))
                .andReturn().getResponse().getContentAsString();

        ApiModels.ExportManifest tampered =
                mapper.readValue(json.replace("\"ok\":true", "\"ok\":false"), ApiModels.ExportManifest.class);

        ExportVerifier.Result result = verifier.verify(tampered);
        assertThat(result.valid()).isFalse();
        assertThat(result.problems()).anyMatch(problem -> problem.contains("does not match its commitment"));
    }

    @Test
    @DisplayName("altering an immutable record field is detected by hash recomputation")
    void alteredRecordFieldIsDetected() throws Exception {
        appendAs(asWriter(), "ORIGINAL_EVENT", "resource-1");
        String json = mvc.perform(get("/audit/export").with(asAdmin()).param("actorId", ADVISOR_17))
                .andReturn().getResponse().getContentAsString();

        ApiModels.ExportManifest tampered = mapper.readValue(
                json.replace("ORIGINAL_EVENT", "REWRITTEN_EVT"), ApiModels.ExportManifest.class);

        ExportVerifier.Result result = verifier.verify(tampered);
        assertThat(result.valid()).isFalse();
        assertThat(result.problems()).anyMatch(problem -> problem.startsWith("Record hash mismatch"));
    }

    @Test
    @DisplayName("dropping a record from the middle of the bundle breaks the chain evidence")
    void droppingARecordIsDetected() throws Exception {
        appendAs(asWriter(), "A", "resource-1");
        appendAs(asAdmin(), "B", "resource-2");
        appendAs(asWriter(), "C", "resource-3");

        ApiModels.ExportManifest full = exportFor(ADVISOR_17);
        ApiModels.ExportManifest truncated = new ApiModels.ExportManifest(full.bundleVersion(),
                full.generatedAt(), full.tenantId(), full.selectionType(), full.selectionValue(), full.keyId(),
                full.publicKeyBase64(), full.manifestHash(), full.signatureBase64(),
                java.util.List.of(full.records().get(0), full.records().get(2)));

        ExportVerifier.Result result = verifier.verify(truncated);
        assertThat(result.valid()).isFalse();
        assertThat(result.problems()).anyMatch(problem -> problem.contains("Chain index gap"));
        assertThat(result.problems()).anyMatch(problem -> problem.contains("Manifest hash does not match"));
    }

    @Test
    @DisplayName("a bundle re-signed with an attacker's key fails against the trusted key")
    void bundleSignedWithAnUntrustedKeyIsRejected() throws Exception {
        appendAs(asWriter(), "A", "resource-1");
        ApiModels.ExportManifest genuine = exportFor(ADVISOR_17);

        // An attacker with their own keypair rebuilds the bundle properly: the key id is
        // part of the canonical form, so they recompute the manifest hash over their own
        // header and then sign that. The result is entirely self-consistent.
        SigningKey attacker = SigningKey.generate("attacker-key", Instant.now());
        String attackerCanonical = ExportCanonicalForm.serialize(genuine.bundleVersion(),
                genuine.generatedAt(), genuine.tenantId(), genuine.selectionType(), genuine.selectionValue(),
                attacker.keyId(), genuine.records());
        String attackerHash = Hashing.sha256(attackerCanonical);
        java.security.Signature signature = java.security.Signature.getInstance("Ed25519");
        signature.initSign(attacker.privateKey());
        signature.update(attackerHash.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String forged = java.util.Base64.getEncoder().encodeToString(signature.sign());

        ApiModels.ExportManifest reSigned = new ApiModels.ExportManifest(genuine.bundleVersion(),
                genuine.generatedAt(), genuine.tenantId(), genuine.selectionType(), genuine.selectionValue(),
                attacker.keyId(), attacker.publicKeyBase64(), attackerHash, forged, genuine.records());

        // ...which passes a naive self-check...
        assertThat(verifier.verify(reSigned).valid()).isTrue();
        // ...and fails the moment it is checked against the key the recipient actually trusts.
        ExportVerifier.Result result =
                verifier.verifyAgainstTrustedKey(reSigned, genuine.publicKeyBase64());
        assertThat(result.valid()).isFalse();
        assertThat(result.problems()).anyMatch(problem -> problem.contains("does not match the trusted key"));
    }

    @Test
    @DisplayName("a tampered signature fails verification")
    void tamperedSignatureIsDetected() throws Exception {
        appendAs(asWriter(), "A", "resource-1");
        ApiModels.ExportManifest genuine = exportFor(ADVISOR_17);

        String flipped = genuine.signatureBase64().startsWith("A")
                ? "B" + genuine.signatureBase64().substring(1)
                : "A" + genuine.signatureBase64().substring(1);
        ApiModels.ExportManifest tampered = new ApiModels.ExportManifest(genuine.bundleVersion(),
                genuine.generatedAt(), genuine.tenantId(), genuine.selectionType(), genuine.selectionValue(),
                genuine.keyId(), genuine.publicKeyBase64(), genuine.manifestHash(), flipped, genuine.records());

        assertThat(verifier.verify(tampered).problems())
                .anyMatch(problem -> problem.contains("signature over the manifest hash is not valid"));
    }

    @Test
    @DisplayName("archived records remain exportable and verifiable")
    void archivedRecordsStayVerifiableInExports() throws Exception {
        appendAs(asWriter(), "A", "resource-1");
        mvc.perform(post("/audit/archive").with(asAdmin()).param("olderThanDays", "0"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.archivedCount").value(1));

        ApiModels.ExportManifest manifest = exportFor(ADVISOR_17);
        assertThat(manifest.records()).hasSize(1);
        assertThat(manifest.records().get(0).event().archived()).isTrue();
        assertThat(verifier.verify(manifest).problems()).isEmpty();
    }

    @Test
    @DisplayName("export requires exactly one selector")
    void exportRequiresExactlyOneSelector() throws Exception {
        appendAs(asWriter(), "A", "resource-1");

        mvc.perform(get("/audit/export").with(asAdmin()))
                .andExpect(status().isBadRequest());
        mvc.perform(get("/audit/export").with(asAdmin())
                        .param("actorId", ADVISOR_17).param("resourceId", "resource-1"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("an export selection matching nothing is a 404, not an empty signed bundle")
    void emptySelectionIsNotFound() throws Exception {
        appendAs(asWriter(), "A", "resource-1");

        mvc.perform(get("/audit/export").with(asAdmin()).param("actorId", "nobody-at-all"))
                .andExpect(status().isNotFound());
    }
}
