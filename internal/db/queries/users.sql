-- name: CreateUser :one
INSERT INTO users (username, email, password_hash, is_admin, is_owner)
VALUES (?, ?, ?, ?, ?)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users
WHERE id = ?;

-- name: GetUserByUsername :one
SELECT * FROM users
WHERE username = ?;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = ?;

-- name: GetUserSessionInvalidatedAt :one
SELECT session_invalidated_at FROM users
WHERE id = ?;

-- name: UpdateUser :one
UPDATE users
SET username = ?, email = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING *;

-- name: UpdateUserSessionInvalidatedAt :exec
UPDATE users
SET session_invalidated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: DeleteUser :exec
DELETE FROM users
WHERE id = ?;

-- name: CountUsers :one
SELECT COUNT(*) FROM users;
