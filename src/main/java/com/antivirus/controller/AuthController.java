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

    @GetMapping("/csrf")
    public Map<String, String> csrf(CsrfToken token) {
        return Map.of(
                "headerName", token.getHeaderName(),
                "parameterName", token.getParameterName(),
                "token", token.getToken());
    }

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
     * Called by the frontend immediately after login to drive UI gating.
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