package com.snhu.Module21.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Ensures the Strict-Transport-Security header is emitted whenever requests are
 * marked as secure (MockMvc `.secure(true)` or real HTTPS traffic).
 * Some app servers skip the header when running without TLS, so we enforce it manually.
 */
@Component
public class StrictTransportSecurityFilter extends OncePerRequestFilter {

    private static final String HSTS_VALUE = "max-age=31536000; includeSubDomains; preload";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        boolean secure = request.isSecure()
            || "https".equalsIgnoreCase(request.getHeader("X-Forwarded-Proto"));

        if (secure) {
            response.setHeader("Strict-Transport-Security", HSTS_VALUE);
        }

        filterChain.doFilter(request, response);
    }
}
