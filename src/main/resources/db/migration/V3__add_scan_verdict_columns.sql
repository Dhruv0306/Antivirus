-- Adds tiered-verdict scoring columns to scan_results.
-- Replaces the old binary infected/clean model with CLEAN / SUSPICIOUS / MALICIOUS
-- verdicts backed by a 0-100 aggregate risk score, so the UI and API can distinguish
-- "confirmed threat" from "worth a human look" instead of forcing everything into
-- a single infected flag.
ALTER TABLE scan_results
ADD COLUMN verdict VARCHAR(20) NOT NULL DEFAULT 'CLEAN';
ALTER TABLE scan_results
ADD COLUMN risk_score INT NOT NULL DEFAULT 0;
ALTER TABLE scan_results
ADD COLUMN detection_signals VARCHAR(500);
-- Backfill existing rows so historical "infected" results are not silently downgraded.
UPDATE scan_results
SET verdict = 'MALICIOUS',
    risk_score = 100
WHERE infected = TRUE;