package com.emreaknci.auth.api.dto;

public record LoginRequest(
        String password,
        String usernameOrEmail
) {
}
