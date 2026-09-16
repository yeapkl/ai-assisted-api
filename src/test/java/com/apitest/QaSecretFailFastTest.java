package com.apitest;

import com.apitest.config.AppProperties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * NFR-2: "JWT signing secret loaded from environment/.env ... fail fast if
 * JWT_SECRET_KEY is missing/short" behavior, both as a focused unit check of
 * AppProperties.validate() and as an end-to-end Spring Boot startup check.
 */
class QaSecretFailFastTest {

    @Test
    void nfr2_validateThrowsOnBlankSecret() {
        AppProperties props = new AppProperties();
        props.setJwtSecretKey("");
        assertThrows(IllegalStateException.class, props::validate);
    }

    @Test
    void nfr2_validateThrowsOnNullSecret() {
        AppProperties props = new AppProperties();
        props.setJwtSecretKey(null);
        assertThrows(IllegalStateException.class, props::validate);
    }

    @Test
    void nfr2_validateThrowsOnSecretUnder32Chars() {
        AppProperties props = new AppProperties();
        props.setJwtSecretKey("a".repeat(31));
        assertThrows(IllegalStateException.class, props::validate);
    }

    @Test
    void nfr2_validateAcceptsSecretOfExactly32Chars() {
        AppProperties props = new AppProperties();
        props.setJwtSecretKey("a".repeat(32));
        assertDoesNotThrow(props::validate);
    }

    @Test
    void nfr2_springBootStartupFailsFastWithMissingSecret() {
        assertThrows(Exception.class, () -> {
            ConfigurableApplicationContext ctx = new SpringApplicationBuilder(ApiApplication.class)
                    .web(WebApplicationType.NONE)
                    .properties("app.jwt-secret-key=", "server.port=0")
                    .run();
            ctx.close(); // should never get here
        }, "Spring Boot startup must fail fast when JWT_SECRET_KEY is missing/blank");
    }

    @Test
    void nfr2_springBootStartupFailsFastWithTooShortSecret() {
        assertThrows(Exception.class, () -> {
            ConfigurableApplicationContext ctx = new SpringApplicationBuilder(ApiApplication.class)
                    .web(WebApplicationType.NONE)
                    .properties("app.jwt-secret-key=tooshort", "server.port=0")
                    .run();
            ctx.close(); // should never get here
        }, "Spring Boot startup must fail fast when JWT_SECRET_KEY is under 32 characters");
    }
}
