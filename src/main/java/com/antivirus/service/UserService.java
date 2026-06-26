package com.antivirus.service;

import com.antivirus.dto.RegisterRequest;

public interface UserService {

    /**
     * Registers a new USER-role account.
     * 
     * @throws RegistrationException if username/email is taken or passwords do not
     *                               match.
     */
    void register(RegisterRequest request);

    /**
     * Returns the role string ("ADMIN" or "USER") for the given username.
     * Used by the /auth/me endpoint.
     */
    String getRoleForUser(String username);
}