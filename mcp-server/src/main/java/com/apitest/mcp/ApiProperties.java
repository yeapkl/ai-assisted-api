package com.apitest.mcp;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "api")
public class ApiProperties {

    private String baseUrl = "https://hello-world-api-mz5e3hbozq-uc.a.run.app";

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }
}
