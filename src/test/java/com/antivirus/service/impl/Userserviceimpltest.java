package com.antivirus.service.impl;

import com.antivirus.dto.RegisterRequest;
import com.antivirus.model.AppUser;
import com.antivirus.repository.AppUserRepository;
import com.antivirus.service.RegistrationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

    @Mock
    private AppUserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    private UserServiceImpl userService;

    @BeforeEach
    void setUp() {
        userService = new UserServiceImpl(userRepository, passwordEncoder);
        ReflectionTestUtils.setField(userService, "adminUsername", "admin");
        ReflectionTestUtils.setField(userService, "adminPassword", "PlainTextAdminPass1!");
    }

    // ── seedAdminUser ────────────────────────────────────────────────

    @Test
    void seedAdminUser_ShouldCreateAdminWhenNoneExists() {
        when(userRepository.findByUsername("admin")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("PlainTextAdminPass1!")).thenReturn("encoded-password");

        userService.seedAdminUser();

        ArgumentCaptor<AppUser> captor = ArgumentCaptor.forClass(AppUser.class);
        verify(userRepository, times(1)).save(captor.capture());
        AppUser saved = captor.getValue();
        assertEquals("admin", saved.getUsername());
        assertEquals("admin@admin.local", saved.getEmail());
        assertEquals("encoded-password", saved.getPassword());
        assertEquals("ADMIN", saved.getRole());
        assertTrue(saved.isEnabled());
    }

    @Test
    void seedAdminUser_ShouldNotSaveWhenExistingAdminAlreadyHasCorrectRole() {
        AppUser existing = new AppUser();
        existing.setUsername("admin");
        existing.setRole("ADMIN");
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(existing));

        userService.seedAdminUser();

        verify(userRepository, never()).save(any(AppUser.class));
    }

    @Test
    void seedAdminUser_ShouldCorrectRoleWhenExistingAccountHasWrongRole() {
        AppUser existing = new AppUser();
        existing.setUsername("admin");
        existing.setRole("USER");
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(existing));

        userService.seedAdminUser();

        verify(userRepository, times(1)).save(existing);
        assertEquals("ADMIN", existing.getRole());
    }

    // ── loadUserByUsername ──────────────────────────────────────────

    @Test
    void loadUserByUsername_ShouldReturnUserDetailsWhenAccountExists() {
        AppUser appUser = new AppUser();
        appUser.setUsername("testuser");
        appUser.setPassword("encoded-password");
        appUser.setRole("USER");
        appUser.setEnabled(true);
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(appUser));

        UserDetails userDetails = userService.loadUserByUsername("testuser");

        assertEquals("testuser", userDetails.getUsername());
        assertEquals("encoded-password", userDetails.getPassword());
        assertTrue(userDetails.isEnabled());
        assertTrue(userDetails.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_USER")));
    }

    @Test
    void loadUserByUsername_ShouldNormalizeUsernameBeforeLookup() {
        AppUser appUser = new AppUser();
        appUser.setUsername("testuser");
        appUser.setPassword("encoded-password");
        appUser.setRole("USER");
        appUser.setEnabled(true);
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(appUser));

        userService.loadUserByUsername("  TestUser  ");

        verify(userRepository, times(1)).findByUsername("testuser");
    }

    @Test
    void loadUserByUsername_ShouldMarkDisabledWhenAccountIsDisabled() {
        AppUser appUser = new AppUser();
        appUser.setUsername("testuser");
        appUser.setPassword("encoded-password");
        appUser.setRole("USER");
        appUser.setEnabled(false);
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(appUser));

        UserDetails userDetails = userService.loadUserByUsername("testuser");

        assertFalse(userDetails.isEnabled());
    }

    @Test
    void loadUserByUsername_ShouldThrowWhenAccountNotFound() {
        when(userRepository.findByUsername("nonexistent")).thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class,
                () -> userService.loadUserByUsername("nonexistent"));
    }

    // ── register ─────────────────────────────────────────────────────

    @Test
    void register_ShouldSaveNewUserOnHappyPath() {
        RegisterRequest request = new RegisterRequest();
        request.setUsername("newuser");
        request.setEmail("newuser@example.com");
        request.setPassword("password123");
        request.setConfirmPassword("password123");

        when(userRepository.existsByUsername("newuser")).thenReturn(false);
        when(userRepository.existsByEmail("newuser@example.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("encoded-password");

        userService.register(request);

        ArgumentCaptor<AppUser> captor = ArgumentCaptor.forClass(AppUser.class);
        verify(userRepository, times(1)).save(captor.capture());
        AppUser saved = captor.getValue();
        assertEquals("newuser", saved.getUsername());
        assertEquals("newuser@example.com", saved.getEmail());
        assertEquals("encoded-password", saved.getPassword());
        assertEquals("USER", saved.getRole());
        assertTrue(saved.isEnabled());
    }

    @Test
    void register_ShouldRejectDuplicateUsername() {
        RegisterRequest request = new RegisterRequest();
        request.setUsername("existinguser");
        request.setEmail("new@example.com");
        request.setPassword("password123");
        request.setConfirmPassword("password123");

        when(userRepository.existsByUsername("existinguser")).thenReturn(true);

        RegistrationException ex = assertThrows(RegistrationException.class,
                () -> userService.register(request));
        assertEquals("Username is already taken", ex.getMessage());
        verify(userRepository, never()).save(any(AppUser.class));
    }

    @Test
    void register_ShouldRejectDuplicateEmail() {
        RegisterRequest request = new RegisterRequest();
        request.setUsername("newuser");
        request.setEmail("taken@example.com");
        request.setPassword("password123");
        request.setConfirmPassword("password123");

        when(userRepository.existsByUsername("newuser")).thenReturn(false);
        when(userRepository.existsByEmail("taken@example.com")).thenReturn(true);

        RegistrationException ex = assertThrows(RegistrationException.class,
                () -> userService.register(request));
        assertEquals("An account with this email already exists", ex.getMessage());
        verify(userRepository, never()).save(any(AppUser.class));
    }

    @Test
    void register_ShouldRejectMismatchedPasswords() {
        RegisterRequest request = new RegisterRequest();
        request.setUsername("newuser");
        request.setEmail("newuser@example.com");
        request.setPassword("password123");
        request.setConfirmPassword("differentPassword");

        when(userRepository.existsByUsername("newuser")).thenReturn(false);
        when(userRepository.existsByEmail("newuser@example.com")).thenReturn(false);

        RegistrationException ex = assertThrows(RegistrationException.class,
                () -> userService.register(request));
        assertEquals("Passwords do not match", ex.getMessage());
        verify(userRepository, never()).save(any(AppUser.class));
    }

    @Test
    void register_ShouldRejectReservedAdminUsername() {
        RegisterRequest request = new RegisterRequest();
        request.setUsername("admin");
        request.setEmail("someone@example.com");
        request.setPassword("password123");
        request.setConfirmPassword("password123");

        RegistrationException ex = assertThrows(RegistrationException.class,
                () -> userService.register(request));
        assertEquals("Username is not available", ex.getMessage());
        verify(userRepository, never()).save(any(AppUser.class));
        verify(userRepository, never()).existsByUsername(anyString());
    }

    // ── getRoleForUser ───────────────────────────────────────────────

    @Test
    void getRoleForUser_ShouldReturnRoleWhenAccountExists() {
        AppUser appUser = new AppUser();
        appUser.setUsername("testuser");
        appUser.setRole("ADMIN");
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(appUser));

        assertEquals("ADMIN", userService.getRoleForUser("testuser"));
    }

    @Test
    void getRoleForUser_ShouldThrowWhenAccountNotFound() {
        when(userRepository.findByUsername("nonexistent")).thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class,
                () -> userService.getRoleForUser("nonexistent"));
    }
}