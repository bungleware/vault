ALTER TABLE tracks ADD COLUMN public_id TEXT;

UPDATE tracks
SET public_id = SUBSTR(LOWER(HEX(RANDOMBLOB(16))), 1, 21)
WHERE public_id IS NULL OR public_id = '';

CREATE UNIQUE INDEX IF NOT EXISTS idx_tracks_public_id ON tracks(public_id);


