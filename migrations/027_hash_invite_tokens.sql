-- Recreate invite_tokens to store only token hashes
ALTER TABLE invite_tokens RENAME TO invite_tokens_old;

CREATE TABLE invite_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    token_type TEXT NOT NULL CHECK(token_type IN ('invite', 'reset')),
    user_id INTEGER,
    created_by INTEGER NOT NULL,
    email TEXT NOT NULL,
    used BOOLEAN NOT NULL DEFAULT 0,
    used_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

DROP INDEX IF EXISTS idx_invite_tokens_token_hash;
DROP INDEX IF EXISTS idx_invite_tokens_user_id;
DROP INDEX IF EXISTS idx_invite_tokens_created_by;
DROP INDEX IF EXISTS idx_invite_tokens_expires_at;

CREATE INDEX IF NOT EXISTS idx_invite_tokens_token_hash ON invite_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_invite_tokens_user_id ON invite_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_invite_tokens_created_by ON invite_tokens(created_by);
CREATE INDEX IF NOT EXISTS idx_invite_tokens_expires_at ON invite_tokens(expires_at);

DROP TABLE invite_tokens_old;
