package com.antivirus.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Maps to the singleton {@code agent_status} row (see
 * V5__add_agent_status.sql). This table is owned by the privileged
 * system-agent process, it's the only thing that ever writes here, see
 * system-agent's AgentStatusReporter. The web app only ever reads it, no
 * @GeneratedValue on id, no setters exposed beyond what JPA itself needs;
 * this class exists to answer "can the agent actually enforce blocking
 * right now", not to let the web app pretend it can update that state
 * itself.
 */
@Entity
@Table(name = "agent_status")
public class AgentStatus {

    @Id
    private Long id;

    @Column(name = "hosts_file_writable", nullable = false)
    private boolean hostsFileWritable;

    @Column(name = "dns_config_writable", nullable = false)
    private boolean dnsConfigWritable;

    @Column(name = "last_heartbeat_at", nullable = false)
    private LocalDateTime lastHeartbeatAt;

    @Column(name = "last_sync_at")
    private LocalDateTime lastSyncAt;

    @Column(name = "last_sync_error", length = 500)
    private String lastSyncError;

    public Long getId() {
        return id;
    }

    public boolean isHostsFileWritable() {
        return hostsFileWritable;
    }

    public boolean isDnsConfigWritable() {
        return dnsConfigWritable;
    }

    public LocalDateTime getLastHeartbeatAt() {
        return lastHeartbeatAt;
    }

    public LocalDateTime getLastSyncAt() {
        return lastSyncAt;
    }

    public String getLastSyncError() {
        return lastSyncError;
    }
}
