package com.emreaknci.auth.api.dto;


public record LoginResponse(
        String accessToken,
        String refreshToken
) {
}