-- name: CreateSharedProjectOrganization :one
INSERT INTO user_shared_project_organization (
    user_id,
    project_id,
    folder_id,
    custom_order
) VALUES (?, ?, ?, ?)
RETURNING *;

-- name: CreateSharedTrackOrganization :one
INSERT INTO user_shared_track_organization (
    user_id,
    track_id,
    folder_id,
    custom_order
) VALUES (?, ?, ?, ?)
RETURNING *;

-- name: UpdateSharedProjectOrganization :one
UPDATE user_shared_project_organization
SET folder_id = ?,
    custom_order = ?,
    updated_at = CURRENT_TIMESTAMP
WHERE user_id = ? AND project_id = ?
RETURNING *;

-- name: UpdateSharedTrackOrganization :one
UPDATE user_shared_track_organization
SET folder_id = ?,
    custom_order = ?,
    updated_at = CURRENT_TIMESTAMP
WHERE user_id = ? AND track_id = ?
RETURNING *;

-- name: UpsertSharedProjectOrganization :one
INSERT INTO user_shared_project_organization (
    user_id,
    project_id,
    folder_id,
    custom_order
) VALUES (?, ?, ?, ?)
ON CONFLICT(user_id, project_id) DO UPDATE SET
    folder_id = excluded.folder_id,
    custom_order = excluded.custom_order,
    updated_at = CURRENT_TIMESTAMP
RETURNING *;

-- name: UpsertSharedTrackOrganization :one
INSERT INTO user_shared_track_organization (
    user_id,
    track_id,
    folder_id,
    custom_order
) VALUES (?, ?, ?, ?)
ON CONFLICT(user_id, track_id) DO UPDATE SET
    folder_id = excluded.folder_id,
    custom_order = excluded.custom_order,
    updated_at = CURRENT_TIMESTAMP
RETURNING *;

-- name: GetUserSharedProjectOrganization :one
SELECT * FROM user_shared_project_organization
WHERE user_id = ? AND project_id = ?;

-- name: GetUserSharedTrackOrganization :one
SELECT * FROM user_shared_track_organization
WHERE user_id = ? AND track_id = ?;

-- name: ListUserSharedProjectOrganizations :many
SELECT * FROM user_shared_project_organization
WHERE user_id = ?
ORDER BY custom_order ASC, created_at DESC;

-- name: ListUserSharedTrackOrganizations :many
SELECT * FROM user_shared_track_organization
WHERE user_id = ?
ORDER BY custom_order ASC, created_at DESC;

-- name: ListSharedProjectOrganizationsInFolder :many
SELECT * FROM user_shared_project_organization
WHERE user_id = ? AND folder_id = ?
ORDER BY custom_order ASC, created_at DESC;

-- name: ListSharedTrackOrganizationsInFolder :many
SELECT * FROM user_shared_track_organization
WHERE user_id = ? AND folder_id = ?
ORDER BY custom_order ASC, created_at DESC;

-- name: ListSharedProjectOrganizationsAtRoot :many
SELECT * FROM user_shared_project_organization
WHERE user_id = ? AND folder_id IS NULL
ORDER BY custom_order ASC, created_at DESC;

-- name: ListSharedTrackOrganizationsAtRoot :many
SELECT * FROM user_shared_track_organization
WHERE user_id = ? AND folder_id IS NULL
ORDER BY custom_order ASC, created_at DESC;

-- name: DeleteSharedProjectOrganization :exec
DELETE FROM user_shared_project_organization
WHERE user_id = ? AND project_id = ?;

-- name: DeleteSharedTrackOrganization :exec
DELETE FROM user_shared_track_organization
WHERE user_id = ? AND track_id = ?;

-- name: DeleteAllSharedProjectOrganizationsInFolder :exec
DELETE FROM user_shared_project_organization
WHERE user_id = ? AND folder_id = ?;

-- name: DeleteAllSharedTrackOrganizationsInFolder :exec
DELETE FROM user_shared_track_organization
WHERE user_id = ? AND folder_id = ?;

-- name: GetMaxProjectOrderInFolder :one
SELECT COALESCE(MAX(custom_order), -1) as max_order
FROM (
    SELECT p.custom_order as custom_order FROM projects p WHERE p.user_id = ? AND p.folder_id = ?
    UNION ALL
    SELECT o.custom_order as custom_order FROM user_shared_project_organization o WHERE o.user_id = ? AND o.folder_id = ?
) combined;

-- name: GetMaxProjectOrderAtRoot :one
SELECT COALESCE(MAX(custom_order), -1) as max_order
FROM (
    SELECT p.custom_order as custom_order FROM projects p WHERE p.user_id = ? AND p.folder_id IS NULL
    UNION ALL
    SELECT o.custom_order as custom_order FROM user_shared_project_organization o WHERE o.user_id = ? AND o.folder_id IS NULL
) combined;

-- name: GetMaxTrackOrderInFolder :one
SELECT COALESCE(MAX(custom_order), -1) as max_order
FROM user_shared_track_organization
WHERE user_id = ? AND folder_id = ?;

-- name: GetMaxTrackOrderAtRoot :one
SELECT COALESCE(MAX(custom_order), -1) as max_order
FROM user_shared_track_organization
WHERE user_id = ? AND folder_id IS NULL;

-- name: GetMaxOrderInFolder :one
-- Get the maximum custom_order across all item types in a folder
-- This ensures new items are appended after existing projects, tracks, and subfolders
SELECT COALESCE(MAX(max_order), -1) as max_order FROM (
    -- Max order from owned projects
    SELECT COALESCE(MAX(p.custom_order), -1) as max_order
    FROM projects p
    WHERE p.user_id = sqlc.arg(user_id) AND p.folder_id = sqlc.arg(folder_id)
    UNION ALL
    -- Max order from shared projects
    SELECT COALESCE(MAX(spo.custom_order), -1) as max_order
    FROM user_shared_project_organization spo
    WHERE spo.user_id = sqlc.arg(user_id) AND spo.folder_id = sqlc.arg(folder_id)
    UNION ALL
    -- Max order from shared tracks
    SELECT COALESCE(MAX(sto.custom_order), -1) as max_order
    FROM user_shared_track_organization sto
    WHERE sto.user_id = sqlc.arg(user_id) AND sto.folder_id = sqlc.arg(folder_id)
    UNION ALL
    -- Max order from subfolders
    SELECT COALESCE(MAX(f.folder_order), -1) as max_order
    FROM folders f
    WHERE f.user_id = sqlc.arg(user_id) AND f.parent_id = sqlc.arg(folder_id)
);

-- name: GetMaxOrderAtRoot :one
-- Get the maximum custom_order across all item types at root level
SELECT COALESCE(MAX(max_order), -1) as max_order FROM (
    -- Max order from owned projects
    SELECT COALESCE(MAX(p.custom_order), -1) as max_order
    FROM projects p
    WHERE p.user_id = sqlc.arg(user_id) AND p.folder_id IS NULL
    UNION ALL
    -- Max order from shared projects
    SELECT COALESCE(MAX(spo.custom_order), -1) as max_order
    FROM user_shared_project_organization spo
    WHERE spo.user_id = sqlc.arg(user_id) AND spo.folder_id IS NULL
    UNION ALL
    -- Max order from shared tracks
    SELECT COALESCE(MAX(sto.custom_order), -1) as max_order
    FROM user_shared_track_organization sto
    WHERE sto.user_id = sqlc.arg(user_id) AND sto.folder_id IS NULL
    UNION ALL
    -- Max order from root folders
    SELECT COALESCE(MAX(f.folder_order), -1) as max_order
    FROM folders f
    WHERE f.user_id = sqlc.arg(user_id) AND f.parent_id IS NULL
);
