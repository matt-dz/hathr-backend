-- name: UpsertUser :one
INSERT INTO users (spotify_user_id, email)
VALUES ($1, $2)
ON CONFLICT (spotify_user_id)
  DO UPDATE SET email = EXCLUDED.email
RETURNING id, refresh_token;

-- name: CreateMonthlyPlaylist :one
INSERT INTO monthly_playlists(user_id, tracks, year, month, name)
VALUES ($1, $2, $3, $4, $5)
RETURNING id;

-- name: GetUserPlaylists :many
SELECT * FROM monthly_playlists WHERE user_id = $1;

-- name: GetPlaylist :one
SELECT * FROM monthly_playlists WHERE user_id = $1 AND year = $2 AND month = $3;

-- name: GetLatestPrivateKey :one
SELECT * FROM private_keys
ORDER BY kid DESC
LIMIT 1;


-- name: GetPrivateKey :one
SELECT value FROM private_keys WHERE kid = $1;

-- name: UpsertSpotifyCredentials :exec
INSERT INTO spotify_tokens (
  user_id,
  access_token,
  token_type,
  scope,
  refresh_token
)
VALUES (
  $1,
  $2,
  $3,
  $4,
  $5
)
ON CONFLICT (user_id)
DO UPDATE SET
  access_token   = EXCLUDED.access_token,
  token_type     = EXCLUDED.token_type,
  scope          = EXCLUDED.scope,
  refresh_token  = EXCLUDED.refresh_token;
