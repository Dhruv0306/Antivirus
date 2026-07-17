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
    void seedAdminUser_ShouldStorePreHashedPasswordAsIsForAllBcryptPrefixes() {
        // $2a$ / $2b$ / $2y$ are all valid bcrypt identifiers ($2y$ is what
        // PHP's password_hash() and some older bcrypt tooling emit). A
        // pre-hashed ADMIN_PASSWORD using any of them must be stored
        // verbatim, not re-encoded by passwordEncoder.
        String preHashed = "$2y$10$abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz012345";
        ReflectionTestUtils.setField(userService, "adminPassword", preHashed);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.empty());

        userService.seedAdminUser();

        ArgumentCaptor<AppUser> captor = ArgumentCaptor.forClass(AppUser.class);
        verify(userRepository, times(1)).save(captor.capture());
        assertEquals(preHashed, captor.getValue().getPassword());
        verify(passwordEncoder, never()).encode(anyString());
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
        assertEquals("That username or email is not available. Please choose a different one.", ex.getMessage());
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
        assertEquals("That username or email is not available. Please choose a different one.", ex.getMessage());
        verify(userRepository, never()).save(any(AppUser.class));
    }

    // H4 fix: the whole point of this test is that a duplicate-username
    // conflict and a duplicate-email conflict must be indistinguishable to
    // the caller. Before the fix these returned different strings, letting
    // an attacker enumerate which usernames/emails are already registered.
    @Test
    void register_DuplicateUsernameAndDuplicateEmail_ShouldReturnIdenticalMessage() {
        RegisterRequest usernameConflict = new RegisterRequest();
        usernameConflict.setUsername("existinguser");
        usernameConflict.setEmail("unique@example.com");
        usernameConflict.setPassword("password123");
        usernameConflict.setConfirmPassword("password123");
        when(userRepository.existsByUsername("existinguser")).thenReturn(true);

        RegisterRequest emailConflict = new RegisterRequest();
        emailConflict.setUsername("uniqueuser");
        emailConflict.setEmail("taken@example.com");
        emailConflict.setPassword("password123");
        emailConflict.setConfirmPassword("password123");
        when(userRepository.existsByUsername("uniqueuser")).thenReturn(false);
        when(userRepository.existsByEmail("taken@example.com")).thenReturn(true);

        RegistrationException usernameEx = assertThrows(RegistrationException.class,
                () -> userService.register(usernameConflict));
        RegistrationException emailEx = assertThrows(RegistrationException.class,
                () -> userService.register(emailConflict));

        assertEquals(usernameEx.getMessage(), emailEx.getMessage(),
                "username-taken and email-taken must be indistinguishable to the caller");
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
        assertEquals("That username or email is not available. Please choose a different one.", ex.getMessage());
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
