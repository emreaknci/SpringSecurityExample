package com.emreaknci.auth.api.model;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;

@Getter
public enum Role implements GrantedAuthority {
    ROLE_USER("USER"),
    ROLE_ADMIN("ADMIN"),
    ROLE_MOD("MOD"),
    ROLE_FSK("FSK");

    private String value;

    Role(String value) {
        this.value = value;
    }

    @Override
    public String getAuthority() {
        return name();
    }
}
