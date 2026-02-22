-- name: CreateProject :one
INSERT INTO projects (user_id, name, description, quality_override, public_id, author_override, folder_id)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetProject :one
SELECT * FROM projects
WHERE id = ? AND user_id = ?;

-- name: GetProjectByID :one
SELECT * FROM projects
WHERE id = ?;

-- name: ListProjectsByUser :many
SELECT
    p.*,
    u.username as owner_username
FROM projects p
JOIN users u ON p.user_id = u.id
WHERE p.user_id = ?
ORDER BY p.created_at DESC;

-- name: GetProjectByPublicID :one
SELECT
    p.*,
    CASE WHEN EXISTS (
        SELECT 1 FROM user_project_shares ups
        WHERE ups.project_id = p.id
    ) THEN 1 ELSE 0 END as is_shared
FROM projects p
WHERE p.public_id = ? AND p.user_id = ?;

-- name: GetProjectByPublicIDNoFilter :one
SELECT
    p.*,
    CASE WHEN EXISTS (
        SELECT 1 FROM user_project_shares ups
        WHERE ups.project_id = p.id
    ) THEN 1 ELSE 0 END as is_shared
FROM projects p
WHERE p.public_id = ?;

-- name: UpdateProject :one
UPDATE projects
SET name = COALESCE(?, name),
    description = COALESCE(?, description),
    quality_override = ?,
    author_override = ?,
    notes = COALESCE(?, notes),
    notes_author_name = COALESCE(?, notes_author_name),
    notes_updated_at = CASE WHEN ? IS NOT NULL THEN CURRENT_TIMESTAMP ELSE notes_updated_at END,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND user_id = ?
RETURNING *;

-- name: UpdateProjectNotes :one
UPDATE projects
SET notes = ?,
    notes_author_name = ?,
    notes_updated_at = CURRENT_TIMESTAMP,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND user_id = ?
RETURNING *;

-- name: DeleteProject :exec
DELETE FROM projects
WHERE id = ? AND user_id = ?;

-- name: UpdateProjectCover :one
UPDATE projects
SET cover_art_path = ?,
    cover_art_mime = ?,
    cover_art_updated_at = CURRENT_TIMESTAMP,
    cover_processed = TRUE,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING *;

-- name: ClearProjectCover :one
UPDATE projects
SET cover_art_path = NULL,
    cover_art_mime = NULL,
    cover_art_updated_at = NULL,
    cover_processed = FALSE,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING *;

-- name: ListUnprocessedCovers :many
SELECT * FROM projects
WHERE cover_art_path IS NOT NULL AND cover_processed = FALSE;

-- name: MarkCoverProcessed :exec
UPDATE projects
SET cover_processed = TRUE
WHERE id = ?;

-- name: ListRootProjects :many
SELECT
    p.*,
    u.username as owner_username
FROM projects p
JOIN users u ON p.user_id = u.id
WHERE p.user_id = ? AND p.folder_id IS NULL
ORDER BY p.created_at ASC;

-- name: UpdateProjectFolder :one
UPDATE projects
SET folder_id = ?,
    folder_added_at = CASE WHEN ? IS NOT NULL THEN CURRENT_TIMESTAMP ELSE NULL END,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND user_id = ?
RETURNING *;

-- name: UpdateProjectFolderWithTimestamp :one
UPDATE projects
SET folder_id = ?,
    folder_added_at = ?,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND user_id = ?
RETURNING *;

-- name: UpdateProjectCustomOrder :one
UPDATE projects
SET custom_order = ?,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND user_id = ?
RETURNING *;

-- name: ListRootProjectsWithCustomOrder :many
SELECT * FROM projects
WHERE user_id = ? AND folder_id IS NULL
ORDER BY custom_order ASC, created_at DESC;
