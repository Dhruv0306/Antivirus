package com.antivirus.agent;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

/**
 * Plain-Java configuration loader for the system agent. No Spring, no
 * {@code @Value}, this reads a single properties file plus a handful of
 * env-var overrides so the same jar works both under a systemd unit (via
 * {@code /etc/antivirus-agent/agent.properties}) and for quick local
 * testing (via env vars alone, no file required).
 *
 * <p>Precedence, highest first: OS environment variable, properties file,
 * built-in default. Env vars use SCREAMING_SNAKE_CASE of the property key
 * (e.g. {@code db.url} -&gt; {@code DB_URL}), matching the convention
 * already used throughout the web app's own .env files, so the same
 * mental model applies here.
 */
public final class AgentConfig {

    private static final String DEFAULT_CONFIG_PATH = "/etc/antivirus-agent/agent.properties";

    private final Properties properties;

    private AgentConfig(Properties properties) {
        this.properties = properties;
    }

    /**
     * Loads config from (in order of precedence): the path in the
     * {@code AGENT_CONFIG_PATH} env var if set, otherwise
     * {@value #DEFAULT_CONFIG_PATH} if it exists, otherwise built-in
     * defaults plus whatever env vars are set. The file is optional
     * everywhere, missing entirely is a valid state for local testing.
     */
    public static AgentConfig load() throws IOException {
        Properties props = new Properties();
        String configPath = System.getenv().getOrDefault("AGENT_CONFIG_PATH", DEFAULT_CONFIG_PATH);
        Path path = Path.of(configPath);
        if (Files.exists(path)) {
            try (InputStream in = Files.newInputStream(path)) {
                props.load(in);
            }
        }
        return new AgentConfig(props);
    }

    /** Test/programmatic construction without touching the filesystem. */
    static AgentConfig fromProperties(Properties properties) {
        return new AgentConfig(properties);
    }

    private String get(String propertyKey, String envKey, String defaultValue) {
        String envValue = System.getenv(envKey);
        if (envValue != null && !envValue.isBlank()) {
            return envValue;
        }
        return properties.getProperty(propertyKey, defaultValue);
    }

    public String getDbUrl() {
        // Same default as the web app's dev/local profiles, so this works
        // out of the box against the same H2 file local development uses.
        return get("db.url", "DB_URL", "jdbc:h2:file:./data/antivirus_local;MODE=PostgreSQL");
    }

    public String getDbUser() {
        return get("db.user", "DB_USER", "sa");
    }

    public String getDbPassword() {
        return get("db.password", "DB_PASSWORD", "localh2password");
    }

    public String getHostsFilePath() {
        boolean windows = System.getProperty("os.name", "").toLowerCase().contains("win");
        String platformDefault = windows
                ? "C:/Windows/System32/drivers/etc/hosts"
                : "/etc/hosts";
        return get("hosts.file.path", "HOSTS_FILE_PATH", platformDefault);
    }

    public String getDnsmasqConfPath() {
        return get("dnsmasq.conf.path", "DNSMASQ_CONF_PATH", "/etc/dnsmasq.d/antivirus-blocked.conf");
    }

    public boolean isDnsBlockingEnabled() {
        return Boolean.parseBoolean(get("dns.blocking.enabled", "DNS_BLOCKING_ENABLED", "false"));
    }

    public int getPollIntervalSeconds() {
        try {
            return Integer.parseInt(get("poll.interval.seconds", "POLL_INTERVAL_SECONDS", "30"));
        } catch (NumberFormatException e) {
            return 30;
        }
    }
}
