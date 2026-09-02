-- Store the user-visible upload name separately from the server-side path.
-- Uploaded files are scanned from generated temp files, so deriving fileName
-- from file_path makes API history show scan_<random> names instead of the
-- original browser-provided filename.
ALTER TABLE scan_results
ADD COLUMN file_name VARCHAR(255);
