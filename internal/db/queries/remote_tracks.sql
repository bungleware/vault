-- name: CreateRemoteTrack :one
INSERT INTO remote_tracks (local_user_id, local_project_id, remote_instance_url, remote_track_id, share_token, title, artist, album, cached_metadata)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetRemoteTrack :one
SELECT * FROM remote_tracks
WHERE id = ? AND local_user_id = ?;

-- name: ListRemoteTracksByUser :many
SELECT * FROM remote_tracks
WHERE local_user_id = ?
ORDER BY created_at DESC;

-- name: ListRemoteTracksByProject :many
SELECT * FROM remote_tracks
WHERE local_user_id = ? AND local_project_id = ?
ORDER BY created_at DESC;

-- name: UpdateRemoteTrack :one
UPDATE remote_tracks
SET title = COALESCE(?, title),
    artist = COALESCE(?, artist),
    album = COALESCE(?, album),
    cached_metadata = COALESCE(?, cached_metadata),
    updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND local_user_id = ?
RETURNING *;

-- name: DeleteRemoteTrack :exec
DELETE FROM remote_tracks
WHERE id = ? AND local_user_id = ?;
