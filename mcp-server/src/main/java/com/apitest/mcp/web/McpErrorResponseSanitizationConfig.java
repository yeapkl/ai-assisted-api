package com.apitest.mcp.web;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.springframework.boot.jackson.autoconfigure.JsonMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Pentest fix (docs/pentest/mcp-oauth-pentest-report.md, Finding 2):
 * Spring AI's MCP webmvc transport ({@code
 * org.springframework.ai.mcp.server.webmvc.transport.WebMvcStatelessServerTransport#handlePost},
 * framework-internal code we don't own) responds to a malformed/unrecognized
 * JSON-RPC request by building an {@code io.modelcontextprotocol.spec.McpError}
 * and returning it directly as the response body via {@code
 * ServerResponse.status(...).body(mcpError)} - it never throws, so a
 * {@code @ControllerAdvice}/{@code @ExceptionHandler} (the pattern used by
 * hello-world-api's {@code GlobalExceptionHandler}) never gets a chance to
 * intercept it; nothing here propagates as an uncaught exception for Spring
 * MVC's exception-resolution machinery to catch. Confirmed empirically (see
 * handoff notes) that {@code @ControllerAdvice} does NOT fire for this path.
 * <p>
 * The actual leak: {@code McpError extends RuntimeException}, and when the
 * standard {@code MappingJackson2HttpMessageConverter} serializes it as a
 * plain POJO (Jackson has no special-casing for {@code Throwable}), Jackson's
 * default bean introspection picks up every public getter inherited from
 * {@code Throwable} - {@code getStackTrace()}, {@code getCause()}, {@code
 * getSuppressed()}, {@code getLocalizedMessage()} - in addition to {@code
 * getJsonRpcError()}, producing a body with a full internal stack trace
 * (class names, file/line numbers, framework/container internals) for every
 * malformed or unrecognized JSON-RPC request (empty body, batch/array body,
 * differently-cased/unknown method name - all three reproduced live).
 * <p>
 * Fix: register a Jackson mixin, applied to the same auto-configured {@code
 * JsonMapper}/{@code JsonMapper.Builder} that backs the default JSON
 * {@code HttpMessageConverter} used to write this and any other response
 * body in this app, that suppresses {@code Throwable}'s exception-internals
 * getters repo-wide - not just for {@code McpError} - so this framework
 * default can't resurface as a leak for some other malformed-input class
 * Spring AI adds later (the pentest report's own recommendation). {@code
 * jsonRpcError} (the intended, spec-shaped JSON-RPC error payload) and the
 * plain {@code message} string are left intact; only the raw
 * exception-internals fields are removed.
 * <p>
 * Note on Jackson version: this app (Spring Boot 4.1) serializes JSON via
 * Jackson 3 ({@code tools.jackson.databind}), not classic Jackson 2 - the
 * customizer hook is {@link JsonMapperBuilderCustomizer} /
 * {@code tools.jackson.databind.json.JsonMapper.Builder#addMixIn}, not the
 * Jackson 2 {@code Jackson2ObjectMapperBuilderCustomizer} (which isn't even
 * on this app's classpath - verified empirically, see handoff notes). The
 * classic {@code com.fasterxml.jackson.annotation} annotations (including
 * {@link JsonIgnoreProperties} below) are still recognized by Jackson 3's
 * databind module, so no new annotation dependency was needed.
 */
@Configuration
public class McpErrorResponseSanitizationConfig {

    /**
     * Mixin suppressing the {@link Throwable} getters that leak internals
     * when a {@code Throwable} subclass (such as {@code McpError}) is
     * serialized directly as an HTTP response body instead of being caught
     * and mapped to a sanitized shape.
     */
    @JsonIgnoreProperties({"stackTrace", "cause", "suppressed", "localizedMessage"})
    private interface ThrowableSanitizingMixin {
    }

    @Bean
    public JsonMapperBuilderCustomizer mcpThrowableStackTraceSuppressingJacksonCustomizer() {
        return builder -> builder.addMixIn(Throwable.class, ThrowableSanitizingMixin.class);
    }
}
