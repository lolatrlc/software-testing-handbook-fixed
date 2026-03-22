package com.snhu.Module21.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

/**
 * Spring Security Configuration - Comprehensive Security Hardening
 *
 * SECURITY FEATURES IMPLEMENTED:
 * 1. Content Security Policy (CSP) to prevent XSS attacks
 * 2. X-Frame-Options to prevent clickjacking
 * 3. X-Content-Type-Options to prevent MIME sniffing
 * 4. X-XSS-Protection for additional XSS protection
 * 5. Referrer Policy for privacy protection
 * 6. HTTPS enforcement recommendations
 *
 * @version 1.0.0 (Secure)
 * @since 2025-11-09
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Configure Spring Security filter chain with comprehensive security headers
     * and policies to protect against common web vulnerabilities
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Allow all requests for this demo (in production, implement proper authentication)
            .authorizeHttpRequests(authz -> authz
                .anyRequest().permitAll()
            )

            // Comprehensive security headers configuration
            .headers(headers -> {
                // Content Security Policy - Prevent XSS attacks
                headers.contentSecurityPolicy(csp -> csp
                    .policyDirectives(
                        "default-src 'self'; " +
                        "script-src 'self'; " +
                        "style-src 'self' 'unsafe-inline'; " +
                        "img-src 'self' data: https:; " +
                        "font-src 'self'; " +
                        "connect-src 'self'; " +
                        "frame-ancestors 'none'; " +
                        "form-action 'self'; " +
                        "base-uri 'self'"
                    )
                );

                // Prevent clickjacking attacks
                headers.frameOptions(frame -> frame.deny());

                // Prevent MIME type sniffing - enable nosniff header
                headers.contentTypeOptions(contentType -> { });

                // Enable XSS protection header explicitly
                headers.xssProtection(xss -> { });

                // Control referrer information
                headers.referrerPolicy(referrer -> referrer
                    .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy
                           .STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
                );

                // HTTP Strict Transport Security (HSTS) for HTTPS enforcement
                headers.httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000) // 1 year
                    .preload(true)
                );

                // Additional security headers
                headers.permissionsPolicy(permissions -> permissions
                    .policy("camera=(), microphone=(), geolocation=()")
                );

                headers.addHeaderWriter((request, response) ->
                    response.setHeader("X-XSS-Protection", "1; mode=block"));
            })

            // Disable CSRF for REST API
            // In production with session-based auth, enable CSRF protection
            .csrf(csrf -> csrf.disable())

            // Configure CORS if needed (disabled for demo)
            .cors(cors -> cors.disable());

        return http.build();
    }
}
