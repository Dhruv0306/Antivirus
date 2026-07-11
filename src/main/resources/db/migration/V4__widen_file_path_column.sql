-- V4__widen_file_path_column.sql
-- file_path was VARCHAR(255) since V1. Directory scans on deeply nested
-- paths (common on Windows, e.g. long project directory trees) can exceed
-- that, which either truncates the stored path or fails the insert
-- mid-scan. Widened to a length that comfortably covers real filesystem
-- path limits on all supported OSes.
ALTER TABLE scan_results
ALTER COLUMN file_path VARCHAR(1024);
