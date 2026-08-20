package com.example.audit.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    private static final String BASIC_AUTH_SCHEME = "basicAuth";

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

                                **Authentication:** every `/audit/**` endpoint requires HTTP Basic \
                                credentials. Use the Authorize button below with one of the dev-only \
                                accounts (`writer`/`writer-dev-pass`, `reader`/`reader-dev-pass`, \
                                `admin`/`admin-dev-pass`) or your overridden credentials. See the \
                                README's Authentication & Authorization section for which role each \
                                endpoint requires.
                                """)
                        .version("0.0.1")
                        .contact(new Contact().name("Audit Log Prototype")))
                .addSecurityItem(new SecurityRequirement().addList(BASIC_AUTH_SCHEME))
                .components(new io.swagger.v3.oas.models.Components()
                        .addSecuritySchemes(BASIC_AUTH_SCHEME, new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("basic")
                                .description("HTTP Basic auth. Role required varies by endpoint - "
                                        + "see README.")));
    }
}
