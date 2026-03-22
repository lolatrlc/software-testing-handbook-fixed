package com.snhu.Module21;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Security-specific tests validating all vulnerability fixes
 * Tests for:
 * - SpEL injection prevention
 * - SQL injection prevention
 * - XSS prevention
 * - Array bounds protection
 * - Security headers
 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("Security Tests - Vulnerability Fix Validation")
class SecurityTests {

    @Autowired
    private MockMvc mockMvc;

    // ============== SPEL INJECTION PREVENTION TESTS ==============

    @Test
    @DisplayName("Should prevent SpEL injection")
    @ValueSource(strings={
            "T(java.lang.Runtime).getRuntime().exec('calc')",
            "T(java.lang.System).getProperty('user.home')",
            "T(java.lang.Class).forName('java.lang.Runtime')",
            "${7*7}"
    })
    void testSpelInjectionPrevention(string spelPayload) throws Exception {
        mockMvc.perform(get("/greeting")
                .param("name", spelPayload))
                .andExpect(status().isBadRequest()); // Rejected by validation
    }


    // ============== SQL INJECTION PREVENTION TESTS ==============

    @Test
    @DisplayName("Should prevent SQL injection patterns")
    void testSqlInjectionPatternRejection() throws Exception {
        String sqlPayload = "admin' OR '1'='1";

        mockMvc.perform(get("/greeting")
                .param("name", sqlPayload))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should reject SQL comment patterns")
    void testSqlCommentRejection() throws Exception {
        String sqlPayload = "admin--";

        mockMvc.perform(get("/greeting")
                .param("name", sqlPayload))
                .andExpect(status().isBadRequest());
    }

    // ============== XSS PREVENTION TESTS ==============

    @Test
    @DisplayName("Should prevent XSS - Script tags")
    void testXssPrevention_ScriptTag() throws Exception {
        String xssPayload = "<script>alert('XSS')</script>";

        mockMvc.perform(get("/greeting")
                .param("name", xssPayload))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should prevent XSS - Event handlers")
    void testXssPrevention_EventHandler() throws Exception {
        String xssPayload = "<img src=x onerror=alert('XSS')>";

        mockMvc.perform(get("/greeting")
                .param("name", xssPayload))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should prevent XSS - JavaScript protocol")
    void testXssPrevention_JavaScriptProtocol() throws Exception {
        String xssPayload = "javascript:alert('XSS')";

        mockMvc.perform(get("/greeting")
                .param("name", xssPayload))
                .andExpect(status().isBadRequest());
    }

    // ============== COMMAND INJECTION PREVENTION TESTS ==============

    @Test
    @DisplayName("Should prevent command injection - Pipe character")
    void testCommandInjectionPrevention_Pipe() throws Exception {
        String cmdPayload = "test | ls -la";

        mockMvc.perform(get("/greeting")
                .param("name", cmdPayload))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should prevent command injection - Semicolon")
    void testCommandInjectionPrevention_Semicolon() throws Exception {
        String cmdPayload = "test; rm -rf /";

        mockMvc.perform(get("/greeting")
                .param("name", cmdPayload))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should prevent command injection - Backticks")
    void testCommandInjectionPrevention_Backticks() throws Exception {
        String cmdPayload = "`whoami`";

        mockMvc.perform(get("/greeting")
                .param("name", cmdPayload))
                .andExpect(status().isBadRequest());
    }

    // ============== PATH TRAVERSAL PREVENTION TESTS ==============

    @Test
    @DisplayName("Should prevent path traversal attempts")
    void testPathTraversalPrevention() throws Exception {
        String pathPayload = "../../../etc/passwd";

        mockMvc.perform(get("/greeting")
                .param("name", pathPayload))
                .andExpect(status().isBadRequest());
    }

    // ============== ARRAY BOUNDS PROTECTION TESTS ==============

    @Test
    @DisplayName("Should prevent array index overflow - Very large number")
    void testArrayBoundsProtection_LargeNumber() throws Exception {
        mockMvc.perform(get("/number/2147483647")) // Integer.MAX_VALUE
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should prevent array index underflow - Large negative")
    void testArrayBoundsProtection_LargeNegative() throws Exception {
        mockMvc.perform(get("/number/-2147483648")) // Integer.MIN_VALUE
                .andExpect(status().isBadRequest());
    }

    // ============== SECURITY HEADERS TESTS ==============

    @Test
    @DisplayName("Should include X-Content-Type-Options header")
    void testSecurityHeader_ContentTypeOptions() throws Exception {
        mockMvc.perform(get("/greeting"))
                .andExpect(header().exists("X-Content-Type-Options"));
    }

    @Test
    @DisplayName("Should include X-Frame-Options header")
    void testSecurityHeader_FrameOptions() throws Exception {
        mockMvc.perform(get("/greeting"))
                .andExpect(header().string("X-Frame-Options", "DENY"));
    }

    @Test
    @DisplayName("Should include X-XSS-Protection header")
    void testSecurityHeader_XssProtection() throws Exception {
        mockMvc.perform(get("/greeting"))
                .andExpect(header().string("X-XSS-Protection", "1; mode=block"));
    }

    @Test
    @DisplayName("Should include Content-Security-Policy header")
    void testSecurityHeader_ContentSecurityPolicy() throws Exception {
        mockMvc.perform(get("/greeting"))
                .andExpect(header().exists("Content-Security-Policy"));
    }

    @Test
    @DisplayName("Should include Referrer-Policy header")
    void testSecurityHeader_ReferrerPolicy() throws Exception {
        mockMvc.perform(get("/greeting"))
                .andExpect(header().exists("Referrer-Policy"));
    }

    @Test
    @DisplayName("Should include Strict-Transport-Security header")
    void testSecurityHeader_StrictTransportSecurity() throws Exception {
        mockMvc.perform(get("/greeting").secure(true))  // Mark request as HTTPS
                .andExpect(header().exists("Strict-Transport-Security"));
    }

    // ============== INPUT VALIDATION TESTS ==============

    @Test
    @DisplayName("Should reject excessively long input")
    void testExcessiveLengthRejection() throws Exception {
        String longName = "A".repeat(101); // Exceeds 100 char limit

        mockMvc.perform(get("/greeting")
                .param("name", longName))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should reject empty input after trimming")
    void testEmptyInputRejection() throws Exception {
        mockMvc.perform(get("/greeting")
                .param("name", "   "))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should reject special characters not in whitelist")
    void testSpecialCharacterRejection() throws Exception {
        String[] specialChars = {"@", "#", "$", "%", "^", "&", "*", "(", ")",
                                "[", "]", "{", "}", "\\", "/", "|", ":", ";",
                                "'", "\"", "<", ">", "?", "!", "~", "`", "="};

        for (String specialChar : specialChars) {
            mockMvc.perform(get("/greeting")
                    .param("name", "Test" + specialChar))
                    .andExpect(status().isBadRequest());
        }
    }

    // ============== COMPREHENSIVE ATTACK PAYLOAD TESTS ==============

    @Test
    @DisplayName("Should prevent LDAP injection patterns")
    void testLdapInjectionPrevention() throws Exception {
        String ldapPayload = "admin)(uid=*))(|(uid=*";

        mockMvc.perform(get("/greeting")
                .param("name", ldapPayload))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should prevent NoSQL injection patterns")
    void testNoSqlInjectionPrevention() throws Exception {
        String noSqlPayload = "{$ne: null}";

        mockMvc.perform(get("/greeting")
                .param("name", noSqlPayload))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should prevent XML injection patterns")
    void testXmlInjectionPrevention() throws Exception {
        String xmlPayload = "<!--attack-->";

        mockMvc.perform(get("/greeting")
                .param("name", xmlPayload))
                .andExpect(status().isBadRequest());
    }
}