-- name: UpsertUser :one
INSERT INTO users (spotify_user_id, email)
VALUES ($1, $2)
ON CONFLICT (spotify_user_id)
  DO UPDATE
    SET users.email = email
RETURNING id;

-- name: CreateMonthlyPlaylist :one
INSERT INTO monthly_playlists(user_id, songs, year, month, name)
VALUES ($1, $2, $3, $4, $5)
RETURNING id;

-- name: GetUserPlaylists :many
SELECT * FROM monthly_playlists WHERE user_id = $1;

-- name: GetPlaylist :one
SELECT * FROM monthly_playlists WHERE id = $1;
