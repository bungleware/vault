-- name: CreateTrackFile :one
INSERT INTO track_files (version_id, quality, file_path, file_size, format, bitrate, content_hash, transcoding_status, original_filename)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetTrackFile :one
SELECT * FROM track_files
WHERE version_id = ? AND quality = ?;

-- name: GetCompletedTrackFile :one
SELECT * FROM track_files
WHERE version_id = ? AND quality = ? AND transcoding_status = 'completed';

-- name: ListTrackFilesByVersion :many
SELECT * FROM track_files
WHERE version_id = ?;

-- name: UpdateTranscodingStatus :exec
UPDATE track_files
SET transcoding_status = ?
WHERE id = ?;

-- name: UpdateWaveform :exec
UPDATE track_files
SET waveform = ?
WHERE id = ?;

-- name: UpdateTrackFileSize :exec
UPDATE track_files
SET file_size = ?
WHERE id = ?;

-- name: DeleteTrackFile :exec
DELETE FROM track_files
WHERE id = ?;

-- name: DeleteTrackFilesByVersion :exec
DELETE FROM track_files
WHERE version_id = ?;

-- name: FindFileByContentHash :one
SELECT * FROM track_files
WHERE content_hash = ?
LIMIT 1;

-- name: ListAllTrackFiles :many
SELECT * FROM track_files
ORDER BY id ASC;
