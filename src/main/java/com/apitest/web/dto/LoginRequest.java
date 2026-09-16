package com.apitest.web.dto;

import jakarta.validation.constraints.NotBlank;

/** Request body for {@code POST /api/v1/auth/login} (FR-5). */
public record LoginRequest(

        @NotBlank(message = "username and password are required")
        String username,

        @NotBlank(message = "username and password are required")
        String password
) {
}
