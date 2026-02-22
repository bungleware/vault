-- TRACK SHARE TOKENS

-- name: CreateShareToken :one
INSERT INTO share_tokens (
    token, user_id, track_id, version_id, expires_at, max_access_count,
    allow_editing, allow_downloads, password_hash, visibility_type
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: UpdateShareToken :one
UPDATE share_tokens
SET expires_at = ?,
    max_access_count = ?,
    allow_editing = ?,
    allow_downloads = ?,
    password_hash = ?,
    visibility_type = ?,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND user_id = ?
RETURNING *;

-- name: GetShareToken :one
SELECT * FROM share_tokens
WHERE token = ?;

-- name: GetShareTokenByID :one
SELECT * FROM share_tokens
WHERE id = ? AND user_id = ?;

-- name: GetShareTokenByTrack :one
SELECT * FROM share_tokens
WHERE track_id = ? AND user_id = ?
LIMIT 1;

-- name: ListShareTokensByUser :many
SELECT * FROM share_tokens
WHERE user_id = ?
ORDER BY created_at DESC;

-- name: ListShareTokensWithTrackInfo :many
SELECT
    st.*,
    t.public_id as track_public_id
FROM share_tokens st
JOIN tracks t ON st.track_id = t.id
WHERE st.user_id = ?
ORDER BY st.created_at DESC;

-- name: ListShareTokensByTrack :many
SELECT * FROM share_tokens
WHERE track_id = ?
ORDER BY created_at DESC;

-- name: IncrementAccessCount :exec
UPDATE share_tokens
SET current_access_count = current_access_count + 1,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: DeleteShareToken :exec
DELETE FROM share_tokens
WHERE id = ? AND user_id = ?;

-- name: DeleteShareTokenByTrack :exec
DELETE FROM share_tokens
WHERE track_id = ? AND user_id = ?;

-- PROJECT SHARE TOKENS

-- name: CreateProjectShareToken :one
INSERT INTO project_share_tokens (
    token, user_id, project_id, expires_at, max_access_count,
    allow_editing, allow_downloads, password_hash, visibility_type
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: UpdateProjectShareToken :one
UPDATE project_share_tokens
SET expires_at = ?,
    max_access_count = ?,
    allow_editing = ?,
    allow_downloads = ?,
    password_hash = ?,
    visibility_type = ?,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND user_id = ?
RETURNING *;

-- name: GetProjectShareToken :one
SELECT * FROM project_share_tokens
WHERE token = ?;

-- name: GetProjectShareTokenByID :one
SELECT * FROM project_share_tokens
WHERE id = ? AND user_id = ?;

-- name: GetProjectShareTokenByProject :one
SELECT * FROM project_share_tokens
WHERE project_id = ? AND user_id = ?
LIMIT 1;

-- name: ListProjectShareTokensByUser :many
SELECT * FROM project_share_tokens
WHERE user_id = ?
ORDER BY created_at DESC;

-- name: ListProjectShareTokensWithProjectInfo :many
SELECT
    pst.*,
    p.public_id as project_public_id
FROM project_share_tokens pst
JOIN projects p ON pst.project_id = p.id
WHERE pst.user_id = ?
ORDER BY pst.created_at DESC;

-- name: ListProjectShareTokensByProject :many
SELECT * FROM project_share_tokens
WHERE project_id = ?
ORDER BY created_at DESC;

-- name: IncrementProjectAccessCount :exec
UPDATE project_share_tokens
SET current_access_count = current_access_count + 1,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: DeleteProjectShareToken :exec
DELETE FROM project_share_tokens
WHERE id = ? AND user_id = ?;

-- name: DeleteProjectShareTokenByProject :exec
DELETE FROM project_share_tokens
WHERE project_id = ? AND user_id = ?;

-- VISIBILITY STATUS OPERATIONS

-- name: UpdateTrackVisibility :one
UPDATE tracks
SET visibility_status = ?,
    allow_editing = ?,
    allow_downloads = ?,
    password_hash = ?,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND user_id = ?
RETURNING *;

-- name: UpdateTrackVisibilityByPublicID :one
UPDATE tracks
SET visibility_status = ?,
    allow_editing = ?,
    allow_downloads = ?,
    password_hash = ?,
    updated_at = CURRENT_TIMESTAMP
WHERE public_id = ? AND user_id = ?
RETURNING *;

-- name: UpdateTrackVisibilityByPublicIDNoUserFilter :one
UPDATE tracks
SET visibility_status = ?,
    allow_editing = ?,
    allow_downloads = ?,
    password_hash = ?,
    updated_at = CURRENT_TIMESTAMP
WHERE public_id = ?
RETURNING *;

-- name: UpdateProjectVisibility :one
UPDATE projects
SET visibility_status = ?,
    allow_editing = ?,
    allow_downloads = ?,
    password_hash = ?,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND user_id = ?
RETURNING *;

-- name: UpdateProjectVisibilityByPublicID :one
UPDATE projects
SET visibility_status = ?,
    allow_editing = ?,
    allow_downloads = ?,
    password_hash = ?,
    updated_at = CURRENT_TIMESTAMP
WHERE public_id = ? AND user_id = ?
RETURNING *;

-- name: GetPublicTracks :many
SELECT * FROM tracks
WHERE visibility_status = 'public'
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: GetPublicProjects :many
SELECT * FROM projects
WHERE visibility_status = 'public'
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- FEDERATION TOKENS

-- name: CreateFederationToken :one
INSERT INTO federation_tokens (
    token, origin_instance_url, origin_share_token, local_user_id,
    resource_type, resource_id, remote_user_id, remote_username, expires_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetFederationToken :one
SELECT * FROM federation_tokens
WHERE token = ?;

-- name: GetFederationTokenByID :one
SELECT * FROM federation_tokens
WHERE id = ?;

-- name: ListFederationTokensByUser :many
SELECT * FROM federation_tokens
WHERE local_user_id = ?
ORDER BY created_at DESC;

-- name: ListFederationTokensByOrigin :many
SELECT * FROM federation_tokens
WHERE origin_instance_url = ? AND local_user_id = ?
ORDER BY created_at DESC;

-- name: UpdateFederationTokenLastUsed :exec
UPDATE federation_tokens
SET last_used_at = CURRENT_TIMESTAMP,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: DeleteFederationToken :exec
DELETE FROM federation_tokens
WHERE id = ? AND local_user_id = ?;

-- name: DeleteFederationTokenByToken :exec
DELETE FROM federation_tokens
WHERE token = ?;

-- name: DeleteExpiredFederationTokens :exec
DELETE FROM federation_tokens
WHERE expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP;

-- SHARE ACCESS

-- name: CreateShareAccess :one
INSERT INTO share_access (
    share_type, share_token_id, user_id, user_instance_url,
    federation_token_id, can_edit, can_download
)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetShareAccess :one
SELECT * FROM share_access
WHERE share_type = ? AND share_token_id = ? AND user_id = ? AND COALESCE(user_instance_url, '') = COALESCE(?, '');

-- name: ListShareAccessByUser :many
SELECT * FROM share_access
WHERE user_id = ?
ORDER BY accepted_at DESC;

-- name: ListShareAccessByShare :many
SELECT * FROM share_access
WHERE share_type = ? AND share_token_id = ?
ORDER BY accepted_at DESC;

-- name: UpdateShareAccessLastAccessed :exec
UPDATE share_access
SET last_accessed_at = CURRENT_TIMESTAMP,
    access_count = access_count + 1
WHERE id = ?;

-- name: DeleteShareAccess :exec
DELETE FROM share_access
WHERE id = ? AND user_id = ?;

-- name: DeleteShareAccessByShare :exec
DELETE FROM share_access
WHERE share_type = ? AND share_token_id = ?;

-- WEBSOCKET SESSIONS

-- name: CreateWebSocketSession :one
INSERT INTO websocket_sessions (
    session_id, user_id, user_instance_url, resource_type, resource_id
)
VALUES (?, ?, ?, ?, ?)
RETURNING *;

-- name: GetWebSocketSession :one
SELECT * FROM websocket_sessions
WHERE session_id = ?;

-- name: ListWebSocketSessionsByResource :many
SELECT * FROM websocket_sessions
WHERE resource_type = ? AND resource_id = ?
ORDER BY connected_at DESC;

-- name: UpdateWebSocketHeartbeat :exec
UPDATE websocket_sessions
SET last_heartbeat_at = CURRENT_TIMESTAMP
WHERE session_id = ?;

-- name: DeleteWebSocketSession :exec
DELETE FROM websocket_sessions
WHERE session_id = ?;

-- name: DeleteStaleWebSocketSessions :exec
DELETE FROM websocket_sessions
WHERE last_heartbeat_at < datetime('now', '-5 minutes');

-- INSTANCE CONFIGURATION

-- name: GetInstanceConfig :one
SELECT * FROM instance_config
WHERE id = 1;

-- name: UpdateInstanceConfig :one
UPDATE instance_config
SET instance_url = ?,
    instance_name = ?,
    allow_federation = ?,
    allow_public_shares = ?,
    updated_at = CURRENT_TIMESTAMP
WHERE id = 1
RETURNING *;

-- USER-TO-USER SHARING (SAME INSTANCE)

-- name: CreateUserProjectShare :one
INSERT INTO user_project_shares (project_id, shared_by, shared_to, can_edit, can_download)
VALUES (?, ?, ?, ?, ?)
RETURNING *;

-- name: UpdateUserProjectShare :one
UPDATE user_project_shares
SET can_edit = ?, can_download = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND shared_by = ?
RETURNING *;

-- name: GetUserProjectShare :one
SELECT * FROM user_project_shares
WHERE project_id = ? AND shared_to = ?;

-- name: ListProjectsSharedWithUser :many
SELECT DISTINCT p.* FROM projects p
JOIN user_project_shares ups ON p.id = ups.project_id
WHERE ups.shared_to = ?
ORDER BY p.created_at DESC;

-- name: ListProjectsSharedByUser :many
SELECT * FROM user_project_shares
WHERE shared_by = ?
ORDER BY created_at DESC;

-- name: ListUsersProjectIsSharedWith :many
SELECT * FROM user_project_shares
WHERE project_id = ?
ORDER BY created_at DESC;

-- name: DeleteUserProjectShare :exec
DELETE FROM user_project_shares
WHERE id = ? AND shared_by = ?;

-- name: DeleteUserProjectShareByID :exec
DELETE FROM user_project_shares
WHERE project_id = ? AND shared_to = ?;

-- name: CreateUserTrackShare :one
INSERT INTO user_track_shares (track_id, shared_by, shared_to, can_edit, can_download)
VALUES (?, ?, ?, ?, ?)
RETURNING *;

-- name: UpdateUserTrackShare :one
UPDATE user_track_shares
SET can_edit = ?, can_download = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND shared_by = ?
RETURNING *;

-- name: UpdateUserTrackShareByID :one
UPDATE user_track_shares
SET can_edit = ?, can_download = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING *;

-- name: GetUserTrackShare :one
SELECT * FROM user_track_shares
WHERE track_id = ? AND shared_to = ?;

-- name: GetUserTrackShareByID :one
SELECT * FROM user_track_shares
WHERE id = ?;

-- name: ListTracksSharedWithUser :many
SELECT DISTINCT t.* FROM tracks t
JOIN user_track_shares uts ON t.id = uts.track_id
WHERE uts.shared_to = ?
ORDER BY t.created_at DESC;

-- name: ListTracksSharedByUser :many
SELECT * FROM user_track_shares
WHERE shared_by = ?
ORDER BY created_at DESC;

-- name: ListUsersTrackIsSharedWith :many
SELECT * FROM user_track_shares
WHERE track_id = ?
ORDER BY created_at DESC;

-- name: DeleteUserTrackShare :exec
DELETE FROM user_track_shares
WHERE id = ? AND shared_by = ?;

-- name: DeleteUserTrackShareByShareID :exec
DELETE FROM user_track_shares
WHERE id = ?;

-- name: DeleteUserTrackShareByID :exec
DELETE FROM user_track_shares
WHERE track_id = ? AND shared_to = ?;
