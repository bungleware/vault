-- name: GetNotesByTrack :many
SELECT * FROM notes
WHERE track_id = ?
ORDER BY updated_at DESC;

-- name: GetNotesByProject :many
SELECT * FROM notes
WHERE project_id = ?
ORDER BY updated_at DESC;

-- name: GetUserNoteForTrack :one
SELECT * FROM notes
WHERE user_id = ? AND track_id = ?;

-- name: GetUserNoteForProject :one
SELECT * FROM notes
WHERE user_id = ? AND project_id = ?;

-- name: CreateTrackNote :one
INSERT INTO notes (user_id, track_id, content, author_name)
VALUES (?, ?, ?, ?)
RETURNING *;

-- name: CreateProjectNote :one
INSERT INTO notes (user_id, project_id, content, author_name)
VALUES (?, ?, ?, ?)
RETURNING *;

-- name: UpdateNote :one
UPDATE notes
SET content = ?,
    author_name = ?,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND user_id = ?
RETURNING *;

-- name: DeleteNote :exec
DELETE FROM notes
WHERE id = ? AND user_id = ?;

-- name: UpsertTrackNote :one
INSERT INTO notes (user_id, track_id, content, author_name)
VALUES (?, ?, ?, ?)
ON CONFLICT (user_id, track_id) DO UPDATE SET
    content = excluded.content,
    author_name = excluded.author_name,
    updated_at = CURRENT_TIMESTAMP
RETURNING *;

-- name: UpsertProjectNote :one
INSERT INTO notes (user_id, project_id, content, author_name)
VALUES (?, ?, ?, ?)
ON CONFLICT (user_id, project_id) DO UPDATE SET
    content = excluded.content,
    author_name = excluded.author_name,
    updated_at = CURRENT_TIMESTAMP
RETURNING *;
