package com.antivirus.agent;

import org.junit.jupiter.api.Test;

import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AgentConfigTest {

    @Test
    void shouldReturnBuiltInDefaultsWhenNothingIsConfigured() {
        AgentConfig config = AgentConfig.fromProperties(new Properties());

        assertEquals("sa", config.getDbUser());
        assertEquals("localh2password", config.getDbPassword());
        assertEquals(30, config.getPollIntervalSeconds());
        assertFalse(config.isDnsBlockingEnabled(),
                "DNS blocking must default to disabled, matching the H2-fix precedent in the web app "
                        + "(app.domain-blocking.dns.enabled), a privileged write path should never be on by default");
        assertEquals("/etc/dnsmasq.d/antivirus-blocked.conf", config.getDnsmasqConfPath());
    }

    @Test
    void propertiesFileValuesShouldOverrideDefaults() {
        Properties props = new Properties();
        props.setProperty("db.user", "custom_user");
        props.setProperty("poll.interval.seconds", "60");
        props.setProperty("dns.blocking.enabled", "true");

        AgentConfig config = AgentConfig.fromProperties(props);

        assertEquals("custom_user", config.getDbUser());
        assertEquals(60, config.getPollIntervalSeconds());
        assertTrue(config.isDnsBlockingEnabled());
    }

    @Test
    void invalidPollIntervalShouldFallBackToDefaultRatherThanCrash() {
        Properties props = new Properties();
        props.setProperty("poll.interval.seconds", "not-a-number");

        AgentConfig config = AgentConfig.fromProperties(props);

        assertEquals(30, config.getPollIntervalSeconds());
    }

    @Test
    void hostsFilePathShouldPickAPlatformAppropriateDefault() {
        AgentConfig config = AgentConfig.fromProperties(new Properties());
        String path = config.getHostsFilePath();
        boolean windows = System.getProperty("os.name", "").toLowerCase().contains("win");
        if (windows) {
            assertEquals("C:/Windows/System32/drivers/etc/hosts", path);
        } else {
            assertEquals("/etc/hosts", path);
        }
    }
}
