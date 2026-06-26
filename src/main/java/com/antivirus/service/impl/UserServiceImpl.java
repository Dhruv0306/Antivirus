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
import java.util.Optional;

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

    /**
     * Seeds the admin account on every startup.
     * If the account exists but has the wrong role (e.g. was created as USER
     * during an earlier broken run), the role is corrected to ADMIN.
     */
    @PostConstruct
    @Transactional
    public void seedAdminUser() {
        String normalizedAdmin = adminUsername.trim().toLowerCase(Locale.ROOT);

        Optional<AppUser> existing = userRepository.findByUsername(normalizedAdmin);

        if (existing.isPresent()) {
            AppUser admin = existing.get();
            if (!"ADMIN".equals(admin.getRole())) {
                admin.setRole("ADMIN");
                userRepository.save(admin);
                logger.info("Corrected admin account '{}' role to ADMIN", normalizedAdmin);
            } else {
                logger.debug("Admin account '{}' already exists with correct role", normalizedAdmin);
            }
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

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String normalized = username.trim().toLowerCase(Locale.ROOT);
        AppUser appUser = userRepository.findByUsername(normalized)
                .orElseThrow(() -> new UsernameNotFoundException("No account found for: " + username));

        return User.builder()
                .username(appUser.getUsername())
                .password(appUser.getPassword())
                .roles(appUser.getRole())
                .disabled(!appUser.isEnabled())
                .build();
    }

    @Override
    @Transactional
    public void register(RegisterRequest request) {
        String normalizedUsername = request.getUsername().trim().toLowerCase(Locale.ROOT);
        String normalizedEmail = request.getEmail().trim().toLowerCase(Locale.ROOT);

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