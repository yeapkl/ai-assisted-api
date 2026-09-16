package com.apitest.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Request body for {@code POST /api/v1/auth/register} (FR-4).
 * Validated with Jakarta Bean Validation (NFR-7, NFR-11) instead of the old
 * hand-rolled {@code ApiServer.validateRegisterInput}. Constraints and
 * messages are kept identical to the previous implementation.
 */
public record RegisterRequest(

        @NotBlank(message = "username: field required")
        @Size(min = 3, max = 32, message = "username: length must be between 3 and 32 characters")
        @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "username: must contain only letters, digits, and underscores")
        String username,

        @NotBlank(message = "password: field required")
        @Size(min = 8, max = 128, message = "password: length must be between 8 and 128 characters")
        String password
) {
}
