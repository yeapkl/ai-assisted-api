package com.apitest.mcp.security;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.springframework.util.StreamUtils;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * Buffers the request body so it can be read twice: once by
 * {@link McpToolAuthorizationFilter} to peek at the JSON-RPC {@code method}/
 * tool name (needed to decide whether this particular {@code tools/call}
 * requires a Bearer token - see that class for why per-tool authorization
 * can't be expressed as a Spring Security URL-based rule when every MCP
 * tool is multiplexed behind a single {@code POST /mcp}), and again
 * downstream by Spring AI's own MCP JSON-RPC handling. Plain body-buffering
 * plumbing (a standard servlet-filter pattern), not a hand-rolled security
 * primitive.
 */
class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {

    private final byte[] cachedBody;

    CachedBodyHttpServletRequest(HttpServletRequest request) throws IOException {
        super(request);
        this.cachedBody = StreamUtils.copyToByteArray(request.getInputStream());
    }

    byte[] getCachedBody() {
        return cachedBody;
    }

    @Override
    public ServletInputStream getInputStream() {
        return new CachedBodyServletInputStream(cachedBody);
    }

    @Override
    public BufferedReader getReader() {
        return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
    }

    private static final class CachedBodyServletInputStream extends ServletInputStream {

        private final ByteArrayInputStream buffer;

        CachedBodyServletInputStream(byte[] body) {
            this.buffer = new ByteArrayInputStream(body);
        }

        @Override
        public boolean isFinished() {
            return buffer.available() == 0;
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setReadListener(ReadListener readListener) {
            // Synchronous servlet I/O only - no async read support needed here.
        }

        @Override
        public int read() {
            return buffer.read();
        }
    }
}
