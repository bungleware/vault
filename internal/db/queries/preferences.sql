-- name: CreateUserPreferences :exec
INSERT INTO user_preferences (user_id, default_quality)
VALUES (?, ?);

-- name: GetUserPreferences :one
SELECT * FROM user_preferences
WHERE user_id = ?;

-- name: UpdateUserPreferences :one
UPDATE user_preferences
SET default_quality = COALESCE(sqlc.narg('default_quality'), default_quality),
    disc_colors = COALESCE(sqlc.narg('disc_colors'), disc_colors),
    color_spread = COALESCE(sqlc.narg('color_spread'), color_spread),
    gradient_spread = COALESCE(sqlc.narg('gradient_spread'), gradient_spread),
    color_shift_rotation = COALESCE(sqlc.narg('color_shift_rotation'), color_shift_rotation),
    updated_at = CURRENT_TIMESTAMP
WHERE user_id = sqlc.arg('user_id')
RETURNING *;
