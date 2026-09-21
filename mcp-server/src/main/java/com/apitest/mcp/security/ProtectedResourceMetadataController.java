package com.apitest.mcp.security;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * FR-8: RFC 9728 OAuth 2.0 Protected Resource Metadata - unauthenticated,
 * so a compliant MCP client (or a human debugging a 401) can discover which
 * Authorization Server issues tokens this resource server accepts, without
 * prior out-of-band knowledge.
 */
@RestController
public class ProtectedResourceMetadataController {

    private final OAuthResourceServerProperties properties;

    public ProtectedResourceMetadataController(OAuthResourceServerProperties properties) {
        this.properties = properties;
    }

    @GetMapping("/.well-known/oauth-protected-resource")
    public Map<String, Object> metadata() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("resource", properties.getResourceBaseUrl());
        body.put("authorization_servers", List.of(properties.getIssuerUri()));
        return body;
    }
}
