-- name: CreateInviteToken :one
INSERT INTO invite_tokens (token_hash, token_type, created_by, email, expires_at)
VALUES (?, ?, ?, ?, ?)
RETURNING *;

-- name: CreateResetToken :one
INSERT INTO invite_tokens (token_hash, token_type, user_id, created_by, email, expires_at)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetInviteTokenByToken :one
SELECT * FROM invite_tokens
WHERE token_hash = ?;

-- name: MarkTokenAsUsed :one
UPDATE invite_tokens
SET used = 1, used_at = CURRENT_TIMESTAMP
WHERE id = ? AND used = 0
RETURNING *;

-- name: GetTokensByUser :many
SELECT * FROM invite_tokens
WHERE user_id = ? OR created_by = ?
ORDER BY created_at DESC;

-- name: DeleteExpiredTokens :exec
DELETE FROM invite_tokens
WHERE expires_at < CURRENT_TIMESTAMP AND used = 0;

-- name: GetUserInviteTokens :many
SELECT * FROM invite_tokens
WHERE created_by = ? AND token_type = 'invite'
ORDER BY created_at DESC;
