package com.antivirus.repository;

import com.antivirus.model.AppUser;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jpa.test.autoconfigure.TestEntityManager;
import org.springframework.test.context.TestPropertySource;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@TestPropertySource(properties = "spring.jpa.hibernate.ddl-auto=create-drop")
class AppUserRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private AppUserRepository appUserRepository;

    private AppUser newUser(String username, String email) {
        AppUser user = new AppUser();
        user.setUsername(username);
        user.setPassword("encoded-password");
        user.setEmail(email);
        user.setRole("USER");
        user.setEnabled(true);
        return user;
    }

    @Test
    void findByUsername_ShouldReturnUserWhenExists() {
        entityManager.persistAndFlush(newUser("testuser", "test@example.com"));

        Optional<AppUser> found = appUserRepository.findByUsername("testuser");

        assertThat(found).isPresent();
        assertThat(found.get().getUsername()).isEqualTo("testuser");
        assertThat(found.get().getEmail()).isEqualTo("test@example.com");
    }

    @Test
    void findByUsername_ShouldReturnEmptyWhenNotExists() {
        Optional<AppUser> found = appUserRepository.findByUsername("nonexistent");

        assertThat(found).isEmpty();
    }

    @Test
    void existsByUsername_ShouldReturnTrueWhenUserExists() {
        entityManager.persistAndFlush(newUser("testuser", "test@example.com"));

        assertThat(appUserRepository.existsByUsername("testuser")).isTrue();
    }

    @Test
    void existsByUsername_ShouldReturnFalseWhenUserNotExists() {
        assertThat(appUserRepository.existsByUsername("nonexistent")).isFalse();
    }

    @Test
    void existsByEmail_ShouldReturnTrueWhenEmailExists() {
        entityManager.persistAndFlush(newUser("testuser", "test@example.com"));

        assertThat(appUserRepository.existsByEmail("test@example.com")).isTrue();
    }

    @Test
    void existsByEmail_ShouldReturnFalseWhenEmailNotExists() {
        assertThat(appUserRepository.existsByEmail("nonexistent@example.com")).isFalse();
    }
}