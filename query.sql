-- name: CreateUser :one
INSERT INTO users(spotify_user_id, email)
VALUES ($1, $2)
RETURNING id;

-- name: CreateMonthlyPlaylist :one
INSERT INTO monthly_playlists(user_id, songs, year, month, name)
VALUES ($1, $2, $3, $4, $5)
RETURNING id;
