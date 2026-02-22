-- name: CreateTrack :one
INSERT INTO tracks (user_id, project_id, title, artist, album, public_id)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetTrack :one
SELECT * FROM tracks
WHERE id = ? AND user_id = ?;

-- name: GetTrackByID :one
SELECT * FROM tracks
WHERE id = ?;

-- name: GetTrackByPublicID :one
SELECT * FROM tracks
WHERE public_id = ? AND user_id = ?;

-- name: GetTrackByPublicIDNoFilter :one
SELECT * FROM tracks
WHERE public_id = ?;

-- name: ListTracksByUser :many
SELECT
    t.*,
    COALESCE(tv.version_name, '') as active_version_name,
    tv.duration_seconds as active_version_duration_seconds,
    p.name as project_name,
    tf.waveform as waveform,
    tf.transcoding_status as lossy_transcoding_status
FROM tracks t
LEFT JOIN track_versions tv ON t.active_version_id = tv.id
LEFT JOIN track_files tf ON tv.id = tf.version_id AND tf.quality = 'lossy'
JOIN projects p ON t.project_id = p.id
WHERE p.user_id = ?
ORDER BY t.created_at DESC;

-- name: ListTracksByProject :many
SELECT
    t.*,
    COALESCE(tv.version_name, '') as active_version_name,
    tv.duration_seconds as active_version_duration_seconds,
    p.name as project_name,
    tf.waveform as waveform,
    tf.transcoding_status as lossy_transcoding_status,
    CASE WHEN EXISTS (
        SELECT 1 FROM user_track_shares uts
        WHERE uts.track_id = t.id
    ) OR EXISTS (
        SELECT 1 FROM user_project_shares ups
        WHERE ups.project_id = t.project_id
    ) THEN 1 ELSE 0 END as is_shared
FROM tracks t
LEFT JOIN track_versions tv ON t.active_version_id = tv.id
LEFT JOIN track_files tf ON tv.id = tf.version_id AND tf.quality = 'lossy'
JOIN projects p ON t.project_id = p.id
WHERE t.user_id = ? AND t.project_id = ?
ORDER BY t.track_order ASC;

-- name: UpdateTrack :one
UPDATE tracks
SET title = COALESCE(?, title),
    artist = COALESCE(?, artist),
    album = COALESCE(?, album),
    project_id = COALESCE(?, project_id),
    key = COALESCE(?, key),
    bpm = COALESCE(?, bpm),
    notes = COALESCE(?, notes),
    notes_author_name = COALESCE(?, notes_author_name),
    notes_updated_at = CASE WHEN ? IS NOT NULL THEN CURRENT_TIMESTAMP ELSE notes_updated_at END,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND user_id = ?
RETURNING *;

-- name: UpdateTrackNotes :one
UPDATE tracks
SET notes = ?,
    notes_author_name = ?,
    notes_updated_at = CURRENT_TIMESTAMP,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND user_id = ?
RETURNING *;

-- name: SetActiveVersion :exec
UPDATE tracks
SET active_version_id = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: DeleteTrack :exec
DELETE FROM tracks
WHERE id = ? AND user_id = ?;

-- name: GetTrackWithDetails :one
SELECT
    t.id,
    t.user_id,
    t.project_id,
    t.public_id,
    t.title,
    t.artist,
    t.album,
    t.key,
    t.bpm,
    t.active_version_id,
    t.track_order,
    t.visibility_status,
    t.created_at,
    t.updated_at,
    tv.version_name as active_version_name,
    tv.duration_seconds as active_version_duration_seconds,
    p.name as project_name,
    tf.waveform as waveform,
    tf.transcoding_status as lossy_transcoding_status
FROM tracks t
LEFT JOIN track_versions tv ON t.active_version_id = tv.id
LEFT JOIN track_files tf ON tv.id = tf.version_id AND tf.quality = 'lossy'
JOIN projects p ON t.project_id = p.id
WHERE t.id = ? AND t.user_id = ?;

-- name: UpdateTrackOrder :exec
UPDATE tracks
SET track_order = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: UpdateTrackBPM :exec
UPDATE tracks
SET bpm = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: UpdateTrackAnalysis :exec
UPDATE tracks
SET bpm = ?, key = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: ListTracksWithoutBPM :many
SELECT t.id, t.title, t.artist, t.active_version_id
FROM tracks t
WHERE t.bpm IS NULL AND t.active_version_id IS NOT NULL;

-- name: ListTracksWithoutAnalysis :many
SELECT t.id, t.title, t.artist, t.bpm, t.key, t.active_version_id
FROM tracks t
WHERE (t.bpm IS NULL OR t.key IS NULL) AND t.active_version_id IS NOT NULL;

-- name: ClearTrackAnalysis :exec
UPDATE tracks
SET bpm = NULL, key = NULL, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: ClearAllTracksAnalysis :exec
UPDATE tracks
SET bpm = NULL, key = NULL, updated_at = CURRENT_TIMESTAMP;

-- name: ListPlainTracksByProject :many
SELECT * FROM tracks
WHERE user_id = ? AND project_id = ?
ORDER BY track_order ASC;

-- name: ListTracksByProjectID :many
SELECT * FROM tracks
WHERE project_id = ?
ORDER BY track_order ASC;

-- name: ListTracksWithDetailsByProjectID :many
SELECT
    t.*,
    COALESCE(tv.version_name, '') as active_version_name,
    tv.duration_seconds as active_version_duration_seconds,
    p.name as project_name,
    tf.waveform as waveform,
    tf.transcoding_status as lossy_transcoding_status,
    CASE WHEN EXISTS (
        SELECT 1 FROM user_track_shares uts
        WHERE uts.track_id = t.id
    ) OR EXISTS (
        SELECT 1 FROM user_project_shares ups
        WHERE ups.project_id = t.project_id
    ) THEN 1 ELSE 0 END as is_shared
FROM tracks t
LEFT JOIN track_versions tv ON t.active_version_id = tv.id
LEFT JOIN track_files tf ON tv.id = tf.version_id AND tf.quality = 'lossy'
JOIN projects p ON t.project_id = p.id
WHERE t.project_id = ?
ORDER BY t.track_order ASC;

-- name: GetMaxTrackOrderByProject :one
SELECT COALESCE(MAX(track_order), -1) as max_order
FROM tracks
WHERE project_id = ?;

-- name: SearchTracksAccessibleByUser :many
SELECT DISTINCT
    t.id,
    t.user_id,
    t.project_id,
    t.public_id,
    t.title,
    t.artist,
    t.album,
    t.key,
    t.bpm,
    t.notes,
    t.notes_author_name,
    t.notes_updated_at,
    t.active_version_id,
    t.track_order,
    t.visibility_status,
    t.created_at,
    t.updated_at,
    COALESCE(tv.version_name, '') as active_version_name,
    tv.duration_seconds as active_version_duration_seconds,
    p.name as project_name,
    tf.waveform as waveform,
    tf.transcoding_status as lossy_transcoding_status,
    CASE WHEN EXISTS (
        SELECT 1 FROM user_project_shares ups
        WHERE ups.project_id = t.project_id
        AND ups.shared_to = sqlc.arg(user_id)
    ) THEN 1 ELSE 0 END as is_shared
FROM tracks t
LEFT JOIN track_versions tv ON t.active_version_id = tv.id
LEFT JOIN track_files tf ON tv.id = tf.version_id AND tf.quality = 'lossy'
JOIN projects p ON t.project_id = p.id
WHERE (
    -- User's own projects
    p.user_id = sqlc.arg(user_id)
    OR
    -- Projects shared with user
    EXISTS (
        SELECT 1 FROM user_project_shares ups
        WHERE ups.project_id = p.id
        AND ups.shared_to = sqlc.arg(user_id)
    )
)
AND (
    -- Search filter (case-insensitive)
    sqlc.arg(search_query) = '' OR
    LOWER(t.title) LIKE '%' || LOWER(sqlc.arg(search_query)) || '%' OR
    LOWER(COALESCE(t.artist, '')) LIKE '%' || LOWER(sqlc.arg(search_query)) || '%' OR
    LOWER(p.name) LIKE '%' || LOWER(sqlc.arg(search_query)) || '%'
)
ORDER BY t.updated_at DESC
LIMIT sqlc.arg(limit_count);
