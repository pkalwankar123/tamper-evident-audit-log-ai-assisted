package com.example.audit.service;

import com.example.audit.api.ApiModels;
import com.example.audit.util.CanonicalJson;
import com.example.audit.util.Hashing;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Verifies an export bundle using nothing but the bundle itself and a trusted public
 * key.
 *
 * <p>This is the piece that makes "independently verifiable" a real claim rather than a
 * documentation sentence. It deliberately does not touch the database, the repositories
 * or any service state - it takes a parsed manifest and re-derives every integrity
 * claim from the values printed in it. A recipient can run exactly this code against a
 * bundle handed to them on a USB stick.
 *
 * <p>Five independent checks:
 * <ol>
 *   <li>each record's {@code recordHash} recomputes from its own fields;</li>
 *   <li>consecutive records link ({@code previousHash} matches the predecessor);</li>
 *   <li>each payload matches its commitment, either directly or through a fully
 *       replayed redaction ledger;</li>
 *   <li>the manifest hash recomputes from the canonical form;</li>
 *   <li>the Ed25519 signature over that hash validates under the supplied key.</li>
 * </ol>
 *
 * <p>Passing the bundle's own embedded public key to {@link #verify} proves internal
 * consistency only. Real assurance comes from passing a key obtained out of band, which
 * is why {@link #verifyAgainstTrustedKey} exists as a separate entry point.
 */
public final class ExportVerifier {
    private final CanonicalJson canonicalJson;

    public ExportVerifier(ObjectMapper objectMapper) {
        this.canonicalJson = new CanonicalJson(objectMapper);
    }

    public record Result(boolean valid, List<String> problems) {
        public static Result of(List<String> problems) {
            return new Result(problems.isEmpty(), List.copyOf(problems));
        }
    }

    /** Verifies using the public key embedded in the bundle (self-consistency check). */
    public Result verify(ApiModels.ExportManifest manifest) {
        return verifyAgainstTrustedKey(manifest, manifest.publicKeyBase64());
    }

    /** Verifies using a public key the recipient already trusts. */
    public Result verifyAgainstTrustedKey(ApiModels.ExportManifest manifest, String trustedPublicKeyBase64) {
        List<String> problems = new ArrayList<>();

        if (trustedPublicKeyBase64 == null || trustedPublicKeyBase64.isBlank()) {
            problems.add("No public key supplied to verify against");
        } else if (!trustedPublicKeyBase64.equals(manifest.publicKeyBase64())) {
            problems.add("Bundle was signed with key id '" + manifest.keyId()
                    + "', whose public key does not match the trusted key supplied");
        }

        verifyRecords(manifest, problems);
        verifyManifestHashAndSignature(manifest, trustedPublicKeyBase64, problems);
        return Result.of(problems);
    }

    private void verifyRecords(ApiModels.ExportManifest manifest, List<String> problems) {
        String expectedPrevious = null;
        long expectedIndex = -1;
        for (ApiModels.ExportRecord entry : manifest.records()) {
            ApiModels.AuditEventResponse event = entry.event();

            if (!manifest.tenantId().equals(event.tenantId())) {
                problems.add("Record at index " + event.chainIndex() + " belongs to tenant '"
                        + event.tenantId() + "', not the bundle tenant '" + manifest.tenantId() + "'");
            }

            String recomputed = AuditService.calculateRecordHash(event.tenantId(), event.chainIndex(),
                    event.eventType(), event.actorId(), event.resourceType(), event.resourceId(),
                    event.timestamp(), event.ingestedAt(), event.payloadCommitment(), event.previousHash());
            if (!recomputed.equals(event.recordHash())) {
                problems.add("Record hash mismatch at chain index " + event.chainIndex());
            }

            if (expectedPrevious != null) {
                if (event.chainIndex() != expectedIndex + 1) {
                    problems.add("Chain index gap: expected " + (expectedIndex + 1)
                            + " but the bundle continues at " + event.chainIndex());
                }
                if (!expectedPrevious.equals(event.previousHash())) {
                    problems.add("Broken chain link at index " + event.chainIndex()
                            + ": previousHash does not match the preceding record");
                }
            }
            expectedPrevious = event.recordHash();
            expectedIndex = event.chainIndex();

            verifyPayload(entry, problems);
        }
    }

    private void verifyPayload(ApiModels.ExportRecord entry, List<String> problems) {
        ApiModels.AuditEventResponse event = entry.event();
        String currentPayloadHash = Hashing.sha256(canonicalJson.write(event.payload()));
        List<ApiModels.RedactionEntryView> ledger = entry.redactions();

        if (ledger.isEmpty()) {
            if (!currentPayloadHash.equals(event.payloadCommitment())) {
                problems.add("Payload at index " + event.chainIndex()
                        + " does not match its commitment and no redaction explains the difference");
            }
            return;
        }

        String expectedPayloadHash = event.payloadCommitment();
        String expectedPreviousEntry = AuditService.GENESIS_HASH;
        long expectedSequence = 1;
        for (ApiModels.RedactionEntryView redaction : ledger) {
            if (redaction.sequenceNumber() != expectedSequence) {
                problems.add("Redaction sequence is not contiguous at index " + event.chainIndex());
                return;
            }
            if (!redaction.previousEntryHash().equals(expectedPreviousEntry)) {
                problems.add("Redaction ledger link is invalid at index " + event.chainIndex());
                return;
            }
            if (!redaction.previousPayloadHash().equals(expectedPayloadHash)) {
                problems.add("Redaction payload transition is invalid at index " + event.chainIndex());
                return;
            }
            String recomputed = AuditService.calculateRedactionHash(event.id(), redaction.sequenceNumber(),
                    redaction.fieldPath(), redaction.reason(), redaction.actorId(), redaction.createdAt(),
                    redaction.previousPayloadHash(), redaction.newPayloadHash(), redaction.previousEntryHash());
            if (!recomputed.equals(redaction.entryHash())) {
                problems.add("Redaction entry hash is invalid at index " + event.chainIndex());
                return;
            }
            expectedPayloadHash = redaction.newPayloadHash();
            expectedPreviousEntry = redaction.entryHash();
            expectedSequence++;
        }
        if (!currentPayloadHash.equals(expectedPayloadHash)) {
            problems.add("Payload at index " + event.chainIndex()
                    + " does not match the latest authorized redaction");
        }
    }

    private void verifyManifestHashAndSignature(ApiModels.ExportManifest manifest, String publicKeyBase64,
                                                List<String> problems) {
        String canonical = ExportCanonicalForm.serialize(manifest.bundleVersion(), manifest.generatedAt(),
                manifest.tenantId(), manifest.selectionType(), manifest.selectionValue(), manifest.keyId(),
                manifest.records());
        String recomputed = Hashing.sha256(canonical);
        if (!recomputed.equals(manifest.manifestHash())) {
            problems.add("Manifest hash does not match the canonical form of the bundle contents");
        }
        if (publicKeyBase64 == null || publicKeyBase64.isBlank()) {
            return;
        }
        try {
            PublicKey publicKey = KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyBase64)));
            if (!SigningService.verifyWith(publicKey, manifest.manifestHash(), manifest.signatureBase64())) {
                problems.add("Ed25519 signature over the manifest hash is not valid for the supplied key");
            }
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            problems.add("Supplied public key is unusable: " + exception.getMessage());
        }
    }
}
