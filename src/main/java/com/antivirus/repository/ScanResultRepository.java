package com.antivirus.repository;

import com.antivirus.model.ScanResult;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ScanResultRepository extends JpaRepository<ScanResult, Long> {
    List<ScanResult> findByInfectedTrue();
    List<ScanResult> findByScanType(String scanType);
    List<ScanResult> findByThreatType(String threatType);
} 