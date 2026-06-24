package com.antivirus.controller;

import com.antivirus.dto.AuthUserResponse;
import com.antivirus.dto.RegisterRequest;
import com.antivirus.service.RegistrationException;
import com.antivirus.service.UserService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Returns CSRF token details so the frontend can attach the token to
     * subsequent state-changing requests. Unchanged from before.
     */
    @GetMapping("/csrf")
    public Map<String, String> csrf(CsrfToken token) {
        return Map.of(
                "headerName", token.getHeaderName(),
                "parameterName", token.getParameterName(),
                "token", token.getToken());
    }

    /**
     * Registers a new USER-role account.
     *
     * Flow:
     * 1. @Valid runs Jakarta Validation constraints on RegisterRequest.
     * 2. UserService.register() checks uniqueness and admin-username conflicts.
     * 3. Returns 201 Created on success.
     * 4. Returns 409 Conflict if username/email is already taken.
     * 5. Returns 400 Bad Request if Jakarta Validation fails.
     */
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@Valid @RequestBody RegisterRequest request) {
        try {
            userService.register(request);
            logger.info("New account registered: {}", request.getUsername());
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(Map.of("success", true, "message", "Account created. You can now log in."));
        } catch (RegistrationException ex) {
            logger.warn("Registration rejected for '{}': {}", request.getUsername(), ex.getMessage());
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("success", false, "message", ex.getMessage()));
        }
    }

    /**
     * Returns the authenticated user's username and role.
     * The frontend calls this immediately after a successful login to determine
     * which navigation items and pages to show.
     *
     * Requires any authenticated session — no specific role needed.
     */
    @GetMapping("/me")
    public ResponseEntity<AuthUserResponse> me(Principal principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        String role = userService.getRoleForUser(principal.getName());
        return ResponseEntity.ok(new AuthUserResponse(principal.getName(), role));
    }
}