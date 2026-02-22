-- Add key and bpm columns to tracks table
ALTER TABLE tracks ADD COLUMN key TEXT;
ALTER TABLE tracks ADD COLUMN bpm INTEGER;
