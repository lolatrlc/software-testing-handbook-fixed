package com.snhu.Module21.exception;

import jakarta.validation.ConstraintViolationException;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Converts validation exceptions into consistent HTTP 400 responses so that
 * security tests (and API consumers) receive structured feedback instead of stack traces.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Map<String, Object>> handleConstraintViolation(
            ConstraintViolationException exception) {

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "Validation failed");
        body.put("details", exception.getMessage());

        logger.warn("Constraint violation: {}", exception.getMessage());

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }
}
