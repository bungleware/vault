-- name: GetStorageStatsByUser :one
SELECT
    COALESCE(SUM(tf.file_size), 0) as total_size_bytes,
    COALESCE(SUM(CASE WHEN tf.quality = 'source' THEN tf.file_size ELSE 0 END), 0) as source_size_bytes,
    COALESCE(SUM(CASE WHEN tf.quality = 'lossless' THEN tf.file_size ELSE 0 END), 0) as lossless_size_bytes,
    COALESCE(SUM(CASE WHEN tf.quality = 'lossy' THEN tf.file_size ELSE 0 END), 0) as lossy_size_bytes,
    COUNT(DISTINCT tf.id) as file_count,
    COUNT(DISTINCT t.project_id) as project_count,
    COUNT(DISTINCT t.id) as track_count
FROM track_files tf
INNER JOIN track_versions tv ON tf.version_id = tv.id
INNER JOIN tracks t ON tv.track_id = t.id
WHERE t.user_id = ?;

-- name: GetGlobalStorageStats :one
SELECT
    COALESCE(SUM(tf.file_size), 0) as total_size_bytes,
    COALESCE(SUM(CASE WHEN tf.quality = 'source' THEN tf.file_size ELSE 0 END), 0) as source_size_bytes,
    COALESCE(SUM(CASE WHEN tf.quality = 'lossless' THEN tf.file_size ELSE 0 END), 0) as lossless_size_bytes,
    COALESCE(SUM(CASE WHEN tf.quality = 'lossy' THEN tf.file_size ELSE 0 END), 0) as lossy_size_bytes,
    COUNT(DISTINCT tf.id) as file_count,
    COUNT(DISTINCT t.project_id) as project_count,
    COUNT(DISTINCT t.id) as track_count
FROM track_files tf
INNER JOIN track_versions tv ON tf.version_id = tv.id
INNER JOIN tracks t ON tv.track_id = t.id;
