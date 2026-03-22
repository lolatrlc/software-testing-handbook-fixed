package com.snhu.Module21;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

/**
 * Basic Application Context Tests
 * Ensures the Spring Boot application starts correctly with all security fixes
 */
@SpringBootTest
@TestPropertySource(properties = {
    "server.port=0", // Use random port for testing
    "logging.level.root=WARN"
})
class ApplicationTests {

    @Test
    void contextLoads() {
        // This test verifies that:
        // 1. All dependencies are correctly configured
        // 2. No conflicting beans or configurations
        // 3. Security configuration loads properly
        // 4. Application can start with new Spring Boot 3.x
    }

    @Test
    void applicationStartsWithSecurityConfig() {
        // Verifies that SecurityConfig is loaded and applied
        // The context load itself validates this

        SecurityFilterChain filterChain = context.getBean(SecurityFilterChain.class);
        assertNotNull(filterChain, "Filter needs to be configurate")

    }
}