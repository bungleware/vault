-- name: CreateTrackVersion :one
INSERT INTO track_versions (track_id, version_name, notes, duration_seconds, version_order)
VALUES (?, ?, ?, ?, ?)
RETURNING *;

-- name: GetTrackVersion :one
SELECT * FROM track_versions
WHERE id = ?;

-- name: ListTrackVersions :many
SELECT * FROM track_versions
WHERE track_id = ?
ORDER BY version_order ASC, created_at ASC;

-- name: ListTrackVersionsWithMetadata :many
SELECT 
    tv.*,
    tf_source.file_size as source_file_size,
    tf_source.format as source_format,
    tf_source.bitrate as source_bitrate,
    tf_lossy.transcoding_status as lossy_transcoding_status
FROM track_versions tv
LEFT JOIN track_files tf_source ON tv.id = tf_source.version_id AND tf_source.quality = 'source'
LEFT JOIN track_files tf_lossy ON tv.id = tf_lossy.version_id AND tf_lossy.quality = 'lossy'
WHERE tv.track_id = ?
ORDER BY tv.version_order ASC, tv.created_at ASC;

-- name: UpdateTrackVersion :one
UPDATE track_versions
SET version_name = COALESCE(?, version_name),
    notes = COALESCE(?, notes),
    updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING *;

-- name: DeleteTrackVersion :exec
DELETE FROM track_versions
WHERE id = ?;

-- name: UpdateTrackVersionDuration :exec
UPDATE track_versions
SET duration_seconds = ?,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: CountTrackVersions :one
SELECT COUNT(*) FROM track_versions
WHERE track_id = ?;

-- name: GetTrackVersionWithOwnership :one
SELECT tv.*, t.user_id
FROM track_versions tv
JOIN tracks t ON tv.track_id = t.id
WHERE tv.id = ?;

-- name: GetMaxVersionOrder :one
SELECT COALESCE(MAX(version_order), -1) as max_order
FROM track_versions
WHERE track_id = ?;
