package com.antivirus.service.impl;

import com.antivirus.dto.RegisterRequest;
import com.antivirus.model.AppUser;
import com.antivirus.repository.AppUserRepository;
import com.antivirus.service.RegistrationException;
import com.antivirus.service.UserService;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;

/**
 * Replaces InMemoryUserDetailsManager from SecurityConfig.
 *
 * On startup (@PostConstruct) it seeds the admin account from env vars if it
 * does not already exist in app_users. This makes the transition from the
 * previous in-memory setup transparent: existing admin credentials continue
 * to work with no change to .env.
 */
@Service
public class UserServiceImpl implements UserDetailsService, UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);

    private final AppUserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.admin.username}")
    private String adminUsername;

    @Value("${app.admin.password}")
    private String adminPassword;

    public UserServiceImpl(AppUserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // ── Admin seeding ─────────────────────────────────────────────────────────
    /**
     * Seeds the admin account from env vars on every startup.
     * Idempotent — does nothing if the account already exists.
     * The same password formats accepted by the old SecurityConfig are
     * supported here: plaintext, {bcrypt}-prefixed, and raw $2a$/$2b$ hashes.
     */
    @PostConstruct
    @Transactional
    public void seedAdminUser() {
        String normalizedAdmin = adminUsername.trim().toLowerCase(Locale.ROOT);
        if (userRepository.existsByUsername(normalizedAdmin)) {
            logger.debug("Admin account '{}' already exists — skipping seed", normalizedAdmin);
            return;
        }

        AppUser admin = new AppUser();
        admin.setUsername(normalizedAdmin);
        admin.setEmail(normalizedAdmin + "@admin.local");
        admin.setPassword(resolveStoredPassword(adminPassword.trim()));
        admin.setRole("ADMIN");
        admin.setEnabled(true);
        userRepository.save(admin);
        logger.info("Admin account '{}' seeded into app_users", normalizedAdmin);
    }

    // ── UserDetailsService (Spring Security) ─────────────────────────────────
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String normalized = username.trim().toLowerCase(Locale.ROOT);
        AppUser appUser = userRepository.findByUsername(normalized)
                .orElseThrow(() -> new UsernameNotFoundException("No account found for: " + username));

        return User.builder()
                .username(appUser.getUsername())
                .password(appUser.getPassword())
                .roles(appUser.getRole())       // Spring prefixes with ROLE_
                .disabled(!appUser.isEnabled())
                .build();
    }

    // ── UserService (registration) ────────────────────────────────────────────
    @Override
    @Transactional
    public void register(RegisterRequest request) {
        String normalizedUsername = request.getUsername().trim().toLowerCase(Locale.ROOT);
        String normalizedEmail    = request.getEmail().trim().toLowerCase(Locale.ROOT);

        // Block registration under the reserved admin username
        if (adminUsername.trim().equalsIgnoreCase(normalizedUsername)) {
            throw new RegistrationException("Username is not available");
        }

        if (userRepository.existsByUsername(normalizedUsername)) {
            throw new RegistrationException("Username is already taken");
        }

        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new RegistrationException("An account with this email already exists");
        }

        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new RegistrationException("Passwords do not match");
        }

        AppUser newUser = new AppUser();
        newUser.setUsername(normalizedUsername);
        newUser.setEmail(normalizedEmail);
        newUser.setPassword(passwordEncoder.encode(request.getPassword()));
        newUser.setRole("USER");
        newUser.setEnabled(true);
        userRepository.save(newUser);

        logger.info("New USER account registered: {}", normalizedUsername);
    }

    @Override
    public String getRoleForUser(String username) {
        String normalized = username.trim().toLowerCase(Locale.ROOT);
        return userRepository.findByUsername(normalized)
                .map(AppUser::getRole)
                .orElseThrow(() -> new UsernameNotFoundException("No account found for: " + username));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────
    /**
     * Mirrors the logic that was previously in SecurityConfig.resolveStoredPassword().
     * Supports plaintext, {bcrypt}-prefixed, and raw BCrypt hashes.
     */
    private String resolveStoredPassword(String password) {
        if (password.startsWith("{bcrypt}")) {
            return password.substring("{bcrypt}".length());
        }
        if (password.startsWith("$2a$") || password.startsWith("$2b$")) {
            return password;
        }
        return passwordEncoder.encode(password);
    }
}