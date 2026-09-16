package com.apitest.web.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

/** Request body for {@code POST /api/v1/auth/refresh} (FR-6). */
public record RefreshRequest(

        @NotBlank(message = "refresh_token: field required")
        @JsonProperty("refresh_token")
        String refreshToken
) {
}
