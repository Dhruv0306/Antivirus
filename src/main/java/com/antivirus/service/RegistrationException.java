package com.antivirus.service;

/**
 * Thrown by UserService when registration cannot proceed due to a validation
 * or uniqueness constraint. The controller maps this to HTTP 409 Conflict.
 */
public class RegistrationException extends RuntimeException {

    public RegistrationException(String message) {
        super(message);
    }
}