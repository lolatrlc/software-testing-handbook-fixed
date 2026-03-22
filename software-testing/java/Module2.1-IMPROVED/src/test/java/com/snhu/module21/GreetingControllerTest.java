package com.snhu.Module21;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.http.MediaType;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.hamcrest.Matchers.*;

/**
 * Comprehensive tests for GreetingController
 * Validates all security fixes and proper functionality
 */
@SpringBootTest
@AutoConfigureMockMvc
class GreetingControllerTest {

    @Autowired
    private MockMvc mockMvc;

    // ============== GREETING ENDPOINT TESTS ==============

    @Test
    void testGreetingWithValidName() throws Exception {
        mockMvc.perform(get("/greeting")
                .param("name", "John"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.content").value("Hello, John!"))
                .andExpect(jsonPath("$.id").isNumber());
    }

    @Test
    void testGreetingWithDefaultName() throws Exception {
        mockMvc.perform(get("/greeting"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").value("Hello, World!"));
    }

    @Test
    void testGreetingWithSpecialCharacters() throws Exception {
        mockMvc.perform(get("/greeting")
                .param("name", "John-Doe.Jr"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").value("Hello, John-Doe.Jr!"));
    }

    @Test
    void testGreetingWithMaxLengthName() throws Exception {
        String longName = "A".repeat(100); // Exactly 100 characters
        mockMvc.perform(get("/greeting")
                .param("name", longName))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").value("Hello, " + longName + "!"));
    }

    // ============== NUMBER ENDPOINT TESTS ==============

    @Test
    void testNumberWithValidIndex() throws Exception {
        mockMvc.perform(get("/number/0"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content",
                    containsString("Element at index 0 is: 897")));
    }

    @Test
    void testNumberWithMaxValidIndex() throws Exception {
        mockMvc.perform(get("/number/6"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content",
                    containsString("Element at index 6 is: 75")));
    }

    @Test
    void testNumberWithMiddleIndex() throws Exception {
        mockMvc.perform(get("/number/3"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content",
                    containsString("Element at index 3 is: 90")));
    }

    // ============== HEALTH ENDPOINT TEST ==============

    @Test
    void testHealthEndpoint() throws Exception {
        mockMvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(content().string("OK - Secure Version 1.0.0"));
    }

    // ============== ERROR HANDLING TESTS ==============

    @Test
    void testGreetingWithTooLongName() throws Exception {
        String tooLongName = "A".repeat(101); // Exceeds 100 character limit
        mockMvc.perform(get("/greeting")
                .param("name", tooLongName))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testGreetingWithInvalidCharacters() throws Exception {
        mockMvc.perform(get("/greeting")
                .param("name", "John@Hacker#"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testNumberWithNegativeIndex() throws Exception {
        mockMvc.perform(get("/number/-1"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testNumberWithTooHighIndex() throws Exception {
        mockMvc.perform(get("/number/7"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testNumberWithVeryHighIndex() throws Exception {
        mockMvc.perform(get("/number/999"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testInvalidEndpoint() throws Exception {
        mockMvc.perform(get("/invalid"))
                .andExpect(status().isNotFound());
    }
}