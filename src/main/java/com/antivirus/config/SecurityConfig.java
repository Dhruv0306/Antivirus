package com.antivirus.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.core.Ordered;
import org.springframework.security.config.Customizer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * Spring Security configuration.
 *
 * Key changes from original:
 * - InMemoryUserDetailsManager removed; UserServiceImpl (a @Service
 * implementing
 * UserDetailsService) is auto-discovered by Spring Security.
 * - @EnableMethodSecurity added for @PreAuthorize on admin-only endpoints.
 * - /api/auth/register added to permitAll and to the rate-limit filter.
 * - Role-based rules: USER may only reach scan/file, scan/directory,
 * history/me.
 * - Dev profile skips CORS origin validation so localhost origins work locally.
 * - H2 console is permitAll in dev (no auth dependency for local debugging).
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private static final int AUTH_ATTEMPT_LIMIT = 10;
    private static final Duration AUTH_ATTEMPT_WINDOW = Duration.ofMinutes(1);

    @Autowired
    private Environment environment;

    @Value("${app.cors.allowed-origins:http://localhost:5000,http://localhost:3000}")
    private String allowedOrigins;

    @Value("${app.trusted-proxy-ips:}")
    private String trustedProxyIps;

    private final Cache<String, AttemptWindow> authAttemptWindows = Caffeine.newBuilder()
            .maximumSize(50_000)
            .expireAfterWrite(2, TimeUnit.MINUTES)
            .build();

    /**
     * Skipped in dev profile so localhost origins don't block local startup.
     * Enforced strictly in every other profile.
     */
    @PostConstruct
    public void validateConfig() {
        boolean isDev = Arrays.asList(environment.getActiveProfiles()).contains("dev");
        if (isDev) {
            return;
        }
        if (allowedOrigins == null || allowedOrigins.isBlank()
                || allowedOrigins.contains("localhost")) {
            throw new IllegalStateException(
                    "CORS_ALLOWED_ORIGINS must be set to a real domain in production " +
                            "(e.g. https://app.example.com). Do not use localhost.");
        }
    }

    @Bean
    @Order(2)
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .authorizeHttpRequests(auth -> auth
                        // ── Public ──────────────────────────────────────────────────────────
                        .requestMatchers("/actuator/health").permitAll()
                        .requestMatchers("/api/auth/csrf").permitAll()
                        .requestMatchers("/api/auth/login").permitAll()
                        .requestMatchers("/api/auth/register").permitAll()
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // ── USER + ADMIN ─────────────────────────────────────────────────────
                        .requestMatchers(HttpMethod.POST, "/api/antivirus/scan/file").hasAnyRole("USER", "ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/antivirus/scan/directory").hasAnyRole("USER", "ADMIN")
                        .requestMatchers(HttpMethod.GET, "/api/antivirus/history/me").hasAnyRole("USER", "ADMIN")

                        // ── ADMIN only ───────────────────────────────────────────────────────
                        .requestMatchers("/api/antivirus/**").hasRole("ADMIN")
                        .requestMatchers("/api/network-security/**").hasRole("ADMIN")

                        // ── Any authenticated user (/auth/me, /auth/logout) ──────────────────
                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().denyAll())
                .formLogin(form -> form
                        .loginProcessingUrl("/api/auth/login")
                        .successHandler((request, response, authentication) -> {
                            response.setStatus(HttpStatus.OK.value());
                            response.setContentType("application/json");
                            response.getWriter().write("{\"success\":true}");
                        })
                        .failureHandler((request, response, exception) -> {
                            response.setStatus(HttpStatus.UNAUTHORIZED.value());
                            response.setContentType("application/json");
                            response.getWriter()
                                    .write("{\"success\":false,\"message\":\"Invalid username or password\"}");
                        }))
                .logout(logout -> logout
                        .logoutUrl("/api/auth/logout")
                        .logoutSuccessHandler((request, response, authentication) -> {
                            response.setStatus(HttpStatus.OK.value());
                            response.setContentType("application/json");
                            response.getWriter().write("{\"success\":true}");
                        }))
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives(
                                "default-src 'self'; " +
                                        "base-uri 'self'; " +
                                        "object-src 'none'; " +
                                        "script-src 'self'; " +
                                        "style-src 'self' 'unsafe-inline'; " +
                                        "img-src 'self' data:; " +
                                        "connect-src 'self'; " +
                                        "frame-ancestors 'none';"))
                        .frameOptions(frame -> frame.deny())
                        .contentTypeOptions(Customizer.withDefaults())
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(31536000))
                        .referrerPolicy(ref -> ref
                                .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)));

        return http.build();
    }

    /**
     * Dev-only chain for H2 console — open without auth for local debugging.
     */
    @Bean
    @Profile("dev")
    @Order(1)
    public SecurityFilterChain h2ConsoleFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/h2-console/**")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/h2-console/**").permitAll())
                .csrf(csrf -> csrf.disable())
                .headers(headers -> headers
                        .frameOptions(frame -> frame.sameOrigin()));
        return http.build();
    }

    /**
     * Rate-limits login AND register: 10 POSTs per IP per minute.
     */
    @Bean
    public FilterRegistrationBean<OncePerRequestFilter> authRateLimitFilter() {
        FilterRegistrationBean<OncePerRequestFilter> bean = new FilterRegistrationBean<>();
        bean.setFilter(new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(
                    @SuppressWarnings("null") HttpServletRequest request,
                    @SuppressWarnings("null") HttpServletResponse response,
                    @SuppressWarnings("null") FilterChain filterChain) throws ServletException, IOException {

                if (!"POST".equalsIgnoreCase(request.getMethod())) {
                    filterChain.doFilter(request, response);
                    return;
                }

                String rateLimitKey = resolveRateLimitKey(request);
                AttemptWindow window = authAttemptWindows.get(rateLimitKey, key -> new AttemptWindow());
                if (!window.tryAcquire(AUTH_ATTEMPT_WINDOW, AUTH_ATTEMPT_LIMIT)) {
                    response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                    response.setContentType("application/json");
                    response.getWriter().write(
                            "{\"success\":false,\"message\":\"Too many attempts. Please try again later.\"}");
                    return;
                }
                filterChain.doFilter(request, response);
            }
        });
        bean.addUrlPatterns("/api/auth/login", "/api/auth/register");
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return bean;
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(parseAllowedOrigins());
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization", "Content-Type", "Accept", "X-Requested-With", "X-XSRF-TOKEN"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @SuppressWarnings("null")
    private List<String> parseAllowedOrigins() {
        return Arrays.stream(allowedOrigins.split(","))
                .map(String::trim)
                .filter(origin -> !origin.isEmpty())
                .toList();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    private String resolveRateLimitKey(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        @SuppressWarnings("null")
        Set<String> trustedProxies = Arrays.stream(trustedProxyIps.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());

        String clientIp = remoteAddr;
        if (trustedProxies.contains(remoteAddr)) {
            String xff = request.getHeader("X-Forwarded-For");
            if (xff != null && !xff.isBlank()) {
                String candidate = xff.split(",")[0].trim();
                if (candidate.matches("^[0-9.:a-fA-F]+$")) {
                    clientIp = candidate;
                }
            }
        }

        String username = Optional.ofNullable(request.getParameter("username"))
                .filter(u -> !u.isBlank())
                .orElse("unknown");

        return clientIp + "|" + username.toLowerCase();
    }

    private static final class AttemptWindow {
        private Instant windowStart = Instant.now();
        private int attempts = 0;

        synchronized boolean tryAcquire(Duration window, int maxAttempts) {
            Instant now = Instant.now();
            if (windowStart.plus(window).isBefore(now)) {
                windowStart = now;
                attempts = 0;
            }
            if (attempts >= maxAttempts)
                return false;
            attempts++;
            return true;
        }
    }
}