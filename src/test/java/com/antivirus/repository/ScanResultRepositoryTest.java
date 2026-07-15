package com.antivirus.repository;

import com.antivirus.model.ScanResult;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jpa.test.autoconfigure.TestEntityManager;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.TestPropertySource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@TestPropertySource(properties = "spring.jpa.hibernate.ddl-auto=create-drop")
class ScanResultRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private ScanResultRepository scanResultRepository;

    private ScanResult newScanResult(String filePath, String scanType, boolean infected, String owner) {
        ScanResult scanResult = new ScanResult();
        scanResult.setFilePath(filePath);
        scanResult.setThreatType(infected ? "TROJAN" : "NONE");
        scanResult.setScanType(scanType);
        scanResult.setInfected(infected);
        scanResult.setOwnerUsername(owner);
        return scanResult;
    }

    @Test
    void findByInfectedTrue_ShouldReturnOnlyInfectedResults() {
        entityManager.persist(newScanResult("/tmp/clean.txt", "FILE", false, "alice"));
        entityManager.persist(newScanResult("/tmp/infected.exe", "FILE", true, "alice"));
        entityManager.flush();

        List<ScanResult> infected = scanResultRepository.findByInfectedTrue();

        assertThat(infected).hasSize(1);
        assertThat(infected.get(0).getFilePath()).isEqualTo("/tmp/infected.exe");
    }

    @Test
    void findByScanType_ShouldFilterByScanType() {
        entityManager.persist(newScanResult("/tmp/file1.txt", "FILE", false, "alice"));
        entityManager.persist(newScanResult("/tmp/file2.txt", "FILE", false, "alice"));
        entityManager.persist(newScanResult("/tmp/network.log", "NETWORK", false, "alice"));
        entityManager.flush();

        List<ScanResult> fileScans = scanResultRepository.findByScanType("FILE");

        assertThat(fileScans).hasSize(2);
        assertThat(fileScans).allMatch(r -> "FILE".equals(r.getScanType()));
    }

    @Test
    void findAllByOrderByScanDateTimeDesc_ShouldReturnPagedAndSortedResults() {
        for (int i = 0; i < 15; i++) {
            entityManager.persist(newScanResult("/tmp/file" + i + ".txt", "FILE", false, "alice"));
        }
        entityManager.flush();

        Page<ScanResult> firstPage = scanResultRepository
                .findAllByOrderByScanDateTimeDesc(PageRequest.of(0, 10));

        assertThat(firstPage.getContent()).hasSize(10);
        assertThat(firstPage.getTotalElements()).isEqualTo(15);
        assertThat(firstPage.getTotalPages()).isEqualTo(2);
        assertThat(firstPage.isFirst()).isTrue();

        Page<ScanResult> secondPage = scanResultRepository
                .findAllByOrderByScanDateTimeDesc(PageRequest.of(1, 10));

        assertThat(secondPage.getContent()).hasSize(5);
        assertThat(secondPage.isLast()).isTrue();
    }

    @Test
    void findByOwnerUsernameOrderByScanDateTimeDesc_ShouldReturnOnlyOwnedResults() {
        entityManager.persist(newScanResult("/tmp/alice1.txt", "FILE", false, "alice"));
        entityManager.persist(newScanResult("/tmp/alice2.txt", "FILE", false, "alice"));
        entityManager.persist(newScanResult("/tmp/bob1.txt", "FILE", false, "bob"));
        entityManager.flush();

        Page<ScanResult> aliceResults = scanResultRepository
                .findByOwnerUsernameOrderByScanDateTimeDesc("alice", PageRequest.of(0, 10));

        assertThat(aliceResults.getContent()).hasSize(2);
        assertThat(aliceResults.getContent()).allMatch(r -> "alice".equals(r.getOwnerUsername()));
    }
}
