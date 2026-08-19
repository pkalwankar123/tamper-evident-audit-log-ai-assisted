package com.example.audit.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI auditOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("Tamper-Evident Audit Log API")
                        .description("""
                                Append-only audit log with SHA-256 hash chaining, structured redaction \
                                (separate integrity ledger), chain verification, and Ed25519-signed exports.

                                **How integrity works:** each record stores `previousHash` + `recordHash`. \
                                `GET /audit/verify` recomputes the chain. Direct DB edits fail verification. \
                                Legitimate redactions update payload via API and keep the chain intact.
                                """)
                        .version("0.0.1")
                        .contact(new Contact().name("Audit Log Prototype")));
    }
}
