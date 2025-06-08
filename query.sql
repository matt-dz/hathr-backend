-- name: CreateSpotifyUser :one
INSERT INTO users (spotify_user_id, email, spotify_user_data)
VALUES ($1, $2, $3)
ON CONFLICT (spotify_user_id) DO UPDATE
SET email = users.email -- no op
RETURNING *;

-- name: UpdateUserImage :execrows
UPDATE users
SET image_url = $1
WHERE id = $2;

-- name: GetUserBySpotifyId :one
SELECT * FROM users WHERE spotify_user_id = $1;

-- name: SignUpUser :one
UPDATE users
SET username = $1, display_name = $2, registered_at = now()
WHERE id = $3
RETURNING *;

-- name: SearchUsers :many
SELECT
    sqlc.embed(u),
    f.*
FROM users u
LEFT JOIN friendships f
  ON f.user_a_id = LEAST(@id::uuid,  u.id)
 AND f.user_b_id = GREATEST(@id::uuid, u.id)
WHERE
  similarity(u.username, @username::text) > 0.2
  AND @id::uuid <> u.id
  AND (f.status IS NULL OR f.status <> 'blocked')
ORDER BY similarity(u.username, @username::text) DESC
LIMIT 10;

-- name: CreateMonthlyPlaylist :one
INSERT INTO playlists(user_id, tracks, year, month, name, type)
VALUES ($1, $2, $3, $4, $5, 'monthly')
RETURNING id;

-- name: GetPersonalPlaylists :many
SELECT * FROM playlists WHERE user_id = $1;

-- name: GetUserPlaylists :many
SELECT p.*
FROM playlists p
LEFT JOIN friendships f
  ON (f.user_a_id = LEAST(@searcher_id::uuid, p.user_id) AND f.user_b_id = GREATEST(@searcher_id::uuid, p.user_id))
WHERE
    p.user_id = @user_id::uuid AND
    (f.status IS NULL OR f.status <> 'blocked') AND
    (p.visibility = 'public' OR
    (p.visibility = 'private' AND p.user_id = @searcher_id::uuid));

-- name: GetPlaylist :one
SELECT sqlc.embed(p), sqlc.embed(u)
FROM playlists p
JOIN users u
  ON u.id = p.user_id
WHERE p.id= $1;

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

-- name: GetUserFromSession :one
SELECT * FROM users WHERE refresh_token = $1;


-- name: UpdateVisibility :execrows
UPDATE playlists
    SET visibility = $1
    WHERE id = $2 AND user_id = $3;


-- name: CreateFriendRequest :one
INSERT INTO friendships (
  user_a_id,
  user_b_id,
  requester_id,
  status,
  requested_at,
  responded_at
)
VALUES (
  LEAST(@requester::uuid, @requestee::uuid),
  GREATEST(@requester::uuid, @requestee::uuid),
  @requester::uuid,
  'pending',
  now(),
  NULL
)
RETURNING *;


-- name: DeleteFriendRequest :execrows
DELETE FROM friendships
    WHERE user_a_id = LEAST(@requester_id::uuid, @requestee_id::uuid) AND user_b_id = GREATEST(@requester_id::uuid, @requestee_id::uuid)
    AND status = 'pending';

-- name: AcceptFriendRequest :one
UPDATE friendships
    SET
        status = 'accepted',
        responded_at = NOW()
    WHERE
        status = 'pending' AND
        user_a_id = LEAST(@responder_id::uuid, @respondee_id::uuid) AND
        user_b_id = GREATEST(@responder_id::uuid, @respondee_id::uuid) AND
        requester_id <> @responder_id::uuid
RETURNING *;

-- name: RemoveFriendship :execrows
DELETE FROM friendships
    WHERE user_a_id = LEAST(@user_a_id::uuid, @user_b_id::uuid) AND user_b_id = GREATEST(@user_a_id::uuid, @user_b_id::uuid);

-- name: ListFriends :many
SELECT u.*
FROM friendships f
JOIN users u
  ON (u.id = CASE
        WHEN f.user_a_id = $1 THEN f.user_b_id
        ELSE f.user_a_id
    END)
WHERE (f.user_a_id = LEAST($1, u.id) AND f.user_b_id = GREATEST($1, u.id))
  AND f.status = 'accepted';

-- name: ListRequests :many
SELECT
    sqlc.embed(u),
    sqlc.embed(f)
FROM friendships f
JOIN users u
ON (u.id = CASE
        WHEN f.user_a_id = $1 THEN f.user_b_id
        ELSE f.user_a_id
    END)
WHERE (f.user_a_id = LEAST($1, u.id) AND f.user_b_id = GREATEST($1, u.id))
AND f.status = 'pending';

-- name: ListOutgoingRequests :many
SELECT sqlc.embed(u), sqlc.embed(f)
FROM friendships f
JOIN users u
ON (u.id = CASE
        WHEN f.user_a_id = $1 THEN f.user_b_id
        ELSE f.user_a_id
    END)
WHERE (f.user_a_id = LEAST($1, u.id) AND f.user_b_id = GREATEST($1, u.id))
AND f.requester_id = $1
AND f.status = 'pending';

-- name: ListIncomingRequests :many
SELECT sqlc.embed(u), sqlc.embed(f)
FROM friendships f
JOIN users u
ON (u.id = CASE
        WHEN f.user_a_id = $1 THEN f.user_b_id
        ELSE f.user_a_id
    END)
WHERE (f.user_a_id = LEAST($1, u.id) AND f.user_b_id = GREATEST($1, u.id))
AND f.requester_id <> $1
AND f.status = 'pending';

-- name: GetUserById :one
SELECT u.*
FROM users u
LEFT JOIN friendships f
    ON (
    f.user_a_id = LEAST(@searcher::uuid, u.id) AND f.user_b_id = GREATEST(@searcher::uuid, u.id)
    )
WHERE u.id = @searchee::uuid AND
      (f.status IS NULL OR f.status <> 'blocked');

-- name: GetPersonalProfile :one
SELECT * FROM users WHERE id = $1;

-- name: GetFriendPlaylists :many
WITH friends AS (
    SELECT
        CASE
            WHEN f.user_a_id = $1 THEN f.user_b_id
            ELSE f.user_a_id
        END AS friend_id
    FROM friendships f
    WHERE f.status    = 'accepted'
    AND (f.user_a_id = $1 OR f.user_b_id = $1)
)
SELECT
    sqlc.embed(u),
    p.id AS playlist_id,
    p.type AS playlist_type,
    p.name AS playlist_name,
    p.year AS playlist_year,
    p.week AS playlist_week,
    p.month AS playlist_month,
    p.created_at AS playlist_created_at,
    p.visibility AS playlist_visibility
FROM friends fr
JOIN users u
    ON u.id = fr.friend_id
LEFT JOIN LATERAL (
    SELECT id, type, name, year, week, month, visibility, created_at
    FROM playlists
    WHERE user_id = fr.friend_id AND visibility = 'public'
    ORDER BY created_at DESC
    LIMIT 1
) p ON true
ORDER BY u.username;

-- name: UpdateUserProfile :one
UPDATE users
SET
  username = COALESCE($1, username),
  display_name = COALESCE($2, display_name),
  email = COALESCE(sqlc.narg('email'), email)
WHERE id = $3
RETURNING *;
