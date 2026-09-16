package com.apitest.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.Map;

/**
 * Maps framework exceptions to the API's existing error-response shape,
 * {@code {"error": "<message>"}}, and — per NFR-7/Assumptions §5 — maps Bean
 * Validation failures to {@code 422} rather than Spring's default {@code 400}
 * for {@link MethodArgumentNotValidException}.
 * <p>
 * NFR-9: exception messages returned here are always our own static/field-
 * validation text, never a raw exception message or stack trace that could
 * leak internals or secrets.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidation(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .findFirst()
                .map(FieldError::getDefaultMessage)
                .orElse("Invalid request");
        return ResponseEntity.status(422).body(Map.of("error", message));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, String>> handleMalformedBody(HttpMessageNotReadableException ex) {
        // NFR-7: malformed JSON payloads are a validation failure too -> 422, not 400.
        return ResponseEntity.status(422).body(Map.of("error", "Malformed JSON request"));
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<Map<String, String>> handleMethodNotAllowed(HttpRequestMethodNotSupportedException ex) {
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).body(Map.of("error", "Method not allowed"));
    }

    /**
     * Bug fix: a request to an unmapped route (e.g. a mistyped URL) is a
     * client-side routing error, not a server fault. Before this fix,
     * {@code NoHandlerFoundException}/{@code NoResourceFoundException} fell
     * through to the generic {@code Exception} handler below and was
     * reported as a 500, which also pollutes 5xx-based server-health
     * monitoring. Requires {@code spring.mvc.throw-exception-if-no-handler-found=true}
     * and {@code spring.web.resources.add-mappings=false} (see
     * application.yml) so the exception is actually thrown instead of being
     * silently handled by the default static-resource handler.
     */
    @ExceptionHandler({NoHandlerFoundException.class, NoResourceFoundException.class})
    public ResponseEntity<Map<String, String>> handleNotFound(Exception ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "Not found"));
    }

    /**
     * Bug fix: an unsupported {@code Content-Type} (e.g. {@code text/plain}
     * on a JSON endpoint) is unambiguously a client input error, but
     * previously fell through to the generic {@code Exception} handler and
     * was reported as a 500. Mapped to {@code 415 Unsupported Media Type}
     * rather than folding it into the existing 422 "malformed JSON body"
     * convention: 415 is the specific, standard HTTP status for exactly this
     * condition (RFC 7231 §6.5.13) and is more precise/debuggable for API
     * clients than reusing 422, which this API otherwise reserves for a
     * syntactically-parseable-but-semantically-invalid body (a different
     * failure mode than "you didn't even send the content type we accept").
     */
    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<Map<String, String>> handleUnsupportedMediaType(HttpMediaTypeNotSupportedException ex) {
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                .body(Map.of("error", "Unsupported Content-Type"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handleUnexpected(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Internal server error"));
    }
}
