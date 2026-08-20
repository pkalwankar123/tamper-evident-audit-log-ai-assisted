package com.example.audit.service;

/**
 * Raised when a submitted payload exceeds {@code audit.payload.max-bytes}.
 *
 * <p>Distinct from a generic validation failure so the API can answer 413 rather than
 * 400 - the request was well-formed, it was too big.
 */
public class PayloadTooLargeException extends RuntimeException {
    public PayloadTooLargeException(String message) {
        super(message);
    }
}
