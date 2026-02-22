-- name: CreateFolder :one
INSERT INTO folders (user_id, parent_id, name, folder_order)
VALUES (?, ?, ?, ?)
RETURNING *;

-- name: GetFolder :one
SELECT * FROM folders
WHERE id = ? AND user_id = ?;

-- name: GetFolderByID :one
SELECT * FROM folders
WHERE id = ?;

-- name: ListFoldersByUser :many
SELECT * FROM folders
WHERE user_id = ? AND parent_id IS NULL
ORDER BY folder_order ASC, created_at DESC;

-- name: ListFoldersByParent :many
SELECT * FROM folders
WHERE user_id = ? AND parent_id = ?
ORDER BY folder_order ASC, created_at DESC;

-- name: ListAllFoldersByUser :many
SELECT * FROM folders
WHERE user_id = ?
ORDER BY folder_order ASC, created_at DESC;

-- name: UpdateFolder :one
UPDATE folders
SET name = ?, parent_id = ?, folder_order = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND user_id = ?
RETURNING *;

-- name: UpdateFolderName :one
UPDATE folders
SET name = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND user_id = ?
RETURNING *;

-- name: UpdateFolderParent :one
UPDATE folders
SET parent_id = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND user_id = ?
RETURNING *;

-- name: UpdateFolderOrder :exec
UPDATE folders
SET folder_order = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND user_id = ?;

-- name: DeleteFolder :exec
DELETE FROM folders
WHERE id = ? AND user_id = ?;

-- name: DeleteFolderByID :exec
DELETE FROM folders
WHERE id = ?;

-- name: CheckFolderExists :one
SELECT COUNT(*) as count FROM folders
WHERE id = ? AND user_id = ?;

-- name: CountProjectsInFolder :one
SELECT COUNT(*) as count FROM projects
WHERE folder_id = ?;

-- name: CountSubfoldersInFolder :one
SELECT COUNT(*) as count FROM folders
WHERE parent_id = ?;

-- name: ListProjectsInFolder :many
SELECT
    p.*,
    u.username as owner_username
FROM projects p
JOIN users u ON p.user_id = u.id
WHERE p.folder_id = ? AND p.user_id = ?
ORDER BY p.folder_added_at ASC;
