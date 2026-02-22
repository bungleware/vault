-- Add is_owner column to users table
ALTER TABLE users ADD COLUMN is_owner BOOLEAN NOT NULL DEFAULT 0;

-- Set the first (oldest) user as owner
UPDATE users SET is_owner = 1 WHERE id = (SELECT MIN(id) FROM users LIMIT 1);
