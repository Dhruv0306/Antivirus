package com.antivirus.service;

import com.antivirus.dto.RegisterRequest;

/**
 * Handles user account creation. Spring Security authentication is wired
 * through the UserDetailsService implementation in UserServiceImpl.
 */
public interface UserService {

    /**
     * Registers a new USER-role account.
     *
     * @throws RegistrationException if username/email is already taken,
     *                               passwords do not match, or the requested
     *                               username conflicts with the admin account.
     */
    void register(RegisterRequest request);

    /**
     * Returns the role string ("ADMIN" or "USER") for the given username.
     * Used by the /auth/me endpoint to tell the frontend which role is active.
     *
     * @throws org.springframework.security.core.userdetails.UsernameNotFoundException
     *         if no account exists for the username.
     */
    String getRoleForUser(String username);
}