package com.example.audit.service;

import com.example.audit.api.ApiModels;

import java.util.List;
import java.util.StringJoiner;

/**
 * The exact byte sequence that an export signature covers.
 *
 * <p>Defined as an explicit, line-oriented format rather than "whatever Jackson emits"
 * because the previous approach was not independently reproducible: a recipient would
 * have had to replicate one specific serializer's field ordering, null handling and
 * date format to recompute the hash, which is not a verification story anyone can act
 * on. Here the format is written down, uses only values that appear verbatim in the
 * bundle, and is implemented once - shared by the signer ({@link ExportService}) and by
 * {@link ExportVerifier}, which is the code a recipient runs.
 *
 * <p>Format (UTF-8, {@code \n} separated, no trailing newline):
 * <pre>
 * audit-export-v2|bundleVersion|generatedAt|tenantId|selectionType|selectionValue|keyId
 * R|chainIndex|eventType|actorId|resourceType|resourceId|timestamp|ingestedAt|payloadCommitment|previousHash|recordHash|archived|selected
 * X|chainIndex|sequenceNumber|fieldPath|reason|actorId|createdAt|previousPayloadHash|newPayloadHash|previousEntryHash|entryHash
 * </pre>
 * Record lines appear in ascending chain-index order; each record's redaction lines
 * follow it in ascending sequence order.
 */
public final class ExportCanonicalForm {
    public static final String VERSION_TAG = "audit-export-v2";

    private ExportCanonicalForm() {
    }

    public static String serialize(String bundleVersion, java.time.Instant generatedAt, String tenantId,
                                   String selectionType, String selectionValue, String keyId,
                                   List<ApiModels.ExportRecord> records) {
        StringJoiner lines = new StringJoiner("\n");
        lines.add(String.join("|", VERSION_TAG, bundleVersion, generatedAt.toString(), tenantId, selectionType,
                selectionValue, keyId));
        for (ApiModels.ExportRecord entry : records) {
            ApiModels.AuditEventResponse event = entry.event();
            lines.add(String.join("|", "R", Long.toString(event.chainIndex()), event.eventType(), event.actorId(),
                    event.resourceType(), event.resourceId(), event.timestamp().toString(),
                    event.ingestedAt().toString(), event.payloadCommitment(), event.previousHash(),
                    event.recordHash(), Boolean.toString(event.archived()), Boolean.toString(entry.selected())));
            for (ApiModels.RedactionEntryView redaction : entry.redactions()) {
                lines.add(String.join("|", "X", Long.toString(event.chainIndex()),
                        Long.toString(redaction.sequenceNumber()), redaction.fieldPath(), redaction.reason(),
                        redaction.actorId(), redaction.createdAt().toString(), redaction.previousPayloadHash(),
                        redaction.newPayloadHash(), redaction.previousEntryHash(), redaction.entryHash()));
            }
        }
        return lines.toString();
    }
}
