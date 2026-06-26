package com.antivirus.repository;

import com.antivirus.model.ScanResult;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ScanResultRepository extends JpaRepository<ScanResult, Long> {

    List<ScanResult> findByInfectedTrue();

    Page<ScanResult> findByInfectedTrue(Pageable pageable);

    Page<ScanResult> findAllByOrderByScanDateTimeDesc(Pageable pageable);

    List<ScanResult> findByScanType(String scanType);

    List<ScanResult> findByThreatType(String threatType);

    /**
     * User-scoped history. ownerUsername is stored lowercase by
     * SecurityServiceImpl.resolveCurrentUsername() — normalize before calling.
     */
    Page<ScanResult> findByOwnerUsernameOrderByScanDateTimeDesc(String ownerUsername, Pageable pageable);
}