package com.emreaknci.auth.api.dto;

import com.emreaknci.auth.api.model.Role;

import java.util.Set;

public record RegisterRequest(
        String email,
        String username,
        String password,
        Set<Role> authorities
) {
}
