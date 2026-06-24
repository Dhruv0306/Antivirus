package com.antivirus.dto;

/**
 * Response body for GET /api/auth/me.
 * The frontend uses this to drive role-based UI gating after login.
 */
public class AuthUserResponse {

    private final String username;
    private final String role;

    public AuthUserResponse(String username, String role) {
        this.username = username;
        this.role = role;
    }

    public String getUsername() {
        return username;
    }

    public String getRole() {
        return role;
    }
}