package com.example.audit.config;

import com.example.audit.service.ExportVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Registers the export verifier as a bean without making the verifier itself
 * Spring-dependent - it stays a plain object a recipient can construct with nothing but
 * a Jackson {@code ObjectMapper}.
 */
@Configuration
public class ExportVerificationConfig {

    @Bean
    public ExportVerifier exportVerifier(ObjectMapper objectMapper) {
        return new ExportVerifier(objectMapper);
    }
}
