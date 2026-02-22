-- name: ListAllUsers :many
SELECT * FROM users
ORDER BY created_at DESC;

-- name: UpdateUserRole :one
UPDATE users
SET is_admin = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING *;

-- name: UpdateUsername :one
UPDATE users
SET username = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING *;

-- name: UpdateUserEmail :one
UPDATE users
SET email = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING *;

-- name: UpdateUserPassword :one
UPDATE users
SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING *;

-- name: DeleteUserByID :exec
DELETE FROM users
WHERE id = ?;
