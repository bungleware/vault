-- name: GetInstanceSettings :one
SELECT * FROM instance_settings
WHERE id = 1;

-- name: UpdateInstanceName :one
UPDATE instance_settings
SET name = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = 1
RETURNING *;

-- name: UpsertInstanceSettings :one
INSERT INTO instance_settings (id, name)
VALUES (1, ?)
ON CONFLICT(id) DO UPDATE SET
    name = excluded.name,
    updated_at = CURRENT_TIMESTAMP
RETURNING *;

-- name: GetSessionInvalidatedAt :one
SELECT session_invalidated_at FROM instance_settings WHERE id = 1;

-- name: InvalidateSessions :exec
UPDATE instance_settings
SET session_invalidated_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
WHERE id = 1;
