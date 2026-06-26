package com.antivirus.dto;

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