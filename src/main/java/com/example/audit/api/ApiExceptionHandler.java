package com.example.audit.api;

import com.example.audit.service.IdempotencyConflictException;
import com.example.audit.service.PayloadTooLargeException;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.util.NoSuchElementException;

/**
 * Maps failures onto status codes without leaking internals.
 *
 * <p>Two deliberate choices. Authorization failures raised from the service layer are
 * translated to 403 here - without this they would surface as 500, which both misleads
 * the caller and hides a security event in the error logs. And the detail returned for a
 * denial is a fixed string: the internal messages name tenants and actor ids, which
 * would turn an error response into a probe for what exists.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler({IllegalArgumentException.class, MethodArgumentNotValidException.class,
            ConstraintViolationException.class, MissingServletRequestParameterException.class,
            MethodArgumentTypeMismatchException.class, HttpMessageNotReadableException.class})
    ProblemDetail badRequest(Exception exception) {
        ProblemDetail detail = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        detail.setTitle("Invalid request");
        detail.setDetail(exception.getMessage());
        return detail;
    }

    @ExceptionHandler(AccessDeniedException.class)
    ProblemDetail forbidden(AccessDeniedException exception) {
        ProblemDetail detail = ProblemDetail.forStatus(HttpStatus.FORBIDDEN);
        detail.setTitle("Forbidden");
        detail.setDetail("You are not authorized to perform this operation on this data");
        return detail;
    }

    @ExceptionHandler(NoSuchElementException.class)
    ProblemDetail notFound(NoSuchElementException exception) {
        ProblemDetail detail = ProblemDetail.forStatus(HttpStatus.NOT_FOUND);
        detail.setTitle("Not found");
        detail.setDetail(exception.getMessage());
        return detail;
    }

    @ExceptionHandler(IdempotencyConflictException.class)
    ProblemDetail conflict(IdempotencyConflictException exception) {
        ProblemDetail detail = ProblemDetail.forStatus(HttpStatus.CONFLICT);
        detail.setTitle("Idempotency key conflict");
        detail.setDetail(exception.getMessage());
        return detail;
    }

    @ExceptionHandler(PayloadTooLargeException.class)
    ProblemDetail payloadTooLarge(PayloadTooLargeException exception) {
        ProblemDetail detail = ProblemDetail.forStatus(HttpStatus.PAYLOAD_TOO_LARGE);
        detail.setTitle("Payload too large");
        detail.setDetail(exception.getMessage());
        return detail;
    }
}
