package com.snhu.module21;

import java.util.concurrent.atomic.AtomicLong;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * REST Controller for greeting endpoints - Secure Version
 *
 * SECURITY FIXES APPLIED:
 * 1. CRITICAL: Removed SpEL Expression Parser (CVE-2022-22965 prevention)
 * 2. CRITICAL: Added input validation to prevent injection attacks
 * 3. HIGH: Implemented array bounds checking
 * 4. Added comprehensive logging for security auditing
 * 5. Input sanitization and length restrictions
 *
 * @version 1.0.0 (Secure)
 * @since 2025-11-09
 */
@RestController
@Validated
public class GreetingController {

    private static final Logger logger = LoggerFactory.getLogger(GreetingController.class);
    private static final String TEMPLATE = "Hello, %s!";
    private final AtomicLong counter = new AtomicLong();

    /**
     * SECURITY FIX #1: SpEL Injection Prevention
     *
     * VULNERABLE CODE (REMOVED):
     * ExpressionParser parser = new SpelExpressionParser();
     * Expression exp = parser.parseExpression(name);  // User input directly parsed!
     * String message = (String) exp.getValue();       // Could execute arbitrary code
     *
     * Attack example that would have worked:
     * /greeting?name=T(java.lang.Runtime).getRuntime().exec('rm -rf /')
     *
     * FIX APPLIED:
     * - Removed all SpEL expression parsing
     * - Added input validation with regex pattern
     * - Limited input length to prevent buffer issues
     * - Direct string usage without evaluation
     */
    @GetMapping("/greeting")
    public ResponseEntity<Greeting> greeting(
            @RequestParam(value = "name", defaultValue = "World")
            @NotBlank(message = "Name cannot be blank")
            @Size(min = 1, max = 100, message = "Name must be between 1 and 100 characters")
            @Pattern(
                regexp = "^[a-zA-Z0-9\\s\\-\\.]+$",
                message = "Name must contain only letters, numbers, spaces, hyphens, and periods"
            )
            String name) {

        // SECURITY: Input sanitization
        String sanitizedName = name.trim();

        // Additional check for empty string after trimming
        if (sanitizedName.isEmpty()) {
            logger.warn("SECURITY: Empty name after trimming detected");
            return ResponseEntity.badRequest().body(
                new Greeting(counter.incrementAndGet(), "Name cannot be empty")
            );
        }

        // SECURITY: Block known injection markers that pass regex (e.g., SQL comments)
        String lower = sanitizedName.toLowerCase();
        String[] deniedTokens = {"--", "/*", "*/"};
        for (String token : deniedTokens) {
            if (lower.contains(token)) {
                logger.warn("SECURITY: Disallowed token '{}' detected in input", token);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    new Greeting(counter.incrementAndGet(), "Input contains disallowed characters.")
                );
            }
        }

        // SECURITY: Audit logging for monitoring suspicious activity
        logger.info("Greeting request received for name: '{}' from counter: {}",
                   sanitizedName, counter.get() + 1);

        // SECURE: Direct string formatting without expression evaluation
        Greeting greeting = new Greeting(
            counter.incrementAndGet(),
            String.format(TEMPLATE, sanitizedName)
        );

        return ResponseEntity.ok(greeting);
    }

    /**
     * SECURITY FIX #2: Array Index Out of Bounds Prevention
     *
     * VULNERABLE CODE (FIXED):
     * String message = "Element in the given index is :: "+myArray[id];
     * // No bounds checking - could throw ArrayIndexOutOfBoundsException
     *
     * Attack example that would have crashed:
     * /number/999 or /number/-1
     *
     * FIX APPLIED:
     * - Added validation annotations for min/max values
     * - Explicit bounds checking (defense in depth)
     * - Proper error handling with meaningful messages
     * - No stack trace exposure to users
     */
    @GetMapping("/number/{id}")
    public ResponseEntity<Greeting> number(
            @PathVariable
            @Min(value = 0, message = "Index must be non-negative")
            @Max(value = 6, message = "Index must be between 0 and 6")
            int id) {

        int[] myArray = {897, 56, 78, 90, 12, 123, 75};

        // SECURITY: Defense in depth - explicit bounds checking
        // Even though validation should catch this, we double-check
        if (id < 0 || id >= myArray.length) {
            logger.warn("SECURITY: Invalid array index attempted: {}", id);

            // Return error response without exposing internal details
            Greeting errorResponse = new Greeting(
                counter.incrementAndGet(),
                "Invalid index requested. Please use a value between 0 and 6."
            );

            return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(errorResponse);
        }

        // SECURE: Safe array access after validation
        String message = "Element at index " + id + " is: " + myArray[id];

        logger.info("Number request successful for index: {}, value: {}",
                   id, myArray[id]);

        Greeting greeting = new Greeting(
            counter.incrementAndGet(),
            String.format(TEMPLATE, message)
        );

        return ResponseEntity.ok(greeting);
    }

    /**
     * Health check endpoint
     * Useful for monitoring and load balancer health checks
     */
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("OK - Secure Version 1.0.0");
    }
}
