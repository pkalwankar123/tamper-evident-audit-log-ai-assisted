package com.example.audit.service;

/**
 * Raised when an idempotency key is reused with a different request body.
 *
 * <p>Returning the original record in that case would let a caller hide a new event
 * behind a key it had already used, so this is surfaced as a 409 instead.
 */
public class IdempotencyConflictException extends RuntimeException {
    public IdempotencyConflictException(String message) {
        super(message);
    }
}
