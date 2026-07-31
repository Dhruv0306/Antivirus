package com.antivirus.repository;

import com.antivirus.model.AgentStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Read-only from the web app's side (see AgentStatus). No custom finder
 * needed beyond findById(1L), it's a singleton row.
 */
@Repository
public interface AgentStatusRepository extends JpaRepository<AgentStatus, Long> {
}
