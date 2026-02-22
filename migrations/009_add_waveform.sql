-- Add waveform column to track_files table
-- Waveform is stored as JSON array of height values (0-100)
ALTER TABLE track_files ADD COLUMN waveform TEXT;
