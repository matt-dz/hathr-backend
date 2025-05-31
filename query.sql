-- name: CreateSpotifyUser :one
INSERT INTO users (spotify_user_id, email, spotify_user_data)
VALUES ($1, $2, $3)
ON CONFLICT (spotify_user_id) DO UPDATE
SET email = users.email -- no op
RETURNING *;

-- name: GetUserBySpotifyId :one
SELECT * FROM users WHERE spotify_user_id = $1;

-- name: SignUpUser :one
UPDATE users
SET username = $1, registered_at = now()
WHERE id = $2 AND registered_at IS NULL
RETURNING *;

-- name: UpsertUser :one
INSERT INTO users (spotify_user_id, email, spotify_user_data)
VALUES ($1, $2, $3)
ON CONFLICT (spotify_user_id)
  DO UPDATE SET
    email  = EXCLUDED.email,
    spotify_user_data = EXCLUDED.spotify_user_data
RETURNING id, refresh_token;

-- name: CreateMonthlyPlaylist :one
INSERT INTO monthly_playlists(user_id, tracks, year, month, name)
VALUES ($1, $2, $3, $4, $5)
RETURNING id;

-- name: GetUserPlaylists :many
SELECT * FROM monthly_playlists WHERE user_id = $1;

-- name: GetPlaylist :one
SELECT * FROM monthly_playlists WHERE id = $1;

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
UPDATE monthly_playlists
    SET visibility = $1
    WHERE id = $2 AND user_id = $3;


-- name: CreateFriendRequest :execrows
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
ON CONFLICT (user_a_id, user_b_id)
DO UPDATE
  SET
    status       = 'pending',
    requested_at = now(),
    requester_id = EXCLUDED.requester_id,
    responded_at = NULL
  WHERE friendships.status = 'rejected';


-- name: CancelFriendRequest :execrows
DELETE FROM friendships
    WHERE user_a_id = LEAST(@user_a_id::uuid, @user_b_id::uuid) AND user_b_id = GREATEST(@user_a_id::uuid, @user_b_id::uuid)
    AND status = 'pending'
    AND requester_id = @requester_id::uuid;

-- name: AcceptFriendRequest :execrows
UPDATE friendships
    SET
        status = 'accepted',
        responded_at = NOW()
    WHERE
        status = 'pending' AND
        user_a_id = LEAST(@responder::uuid, @respondee::uuid) AND
        user_b_id = GREATEST(@responder::uuid, @respondee::uuid) AND
        requester_id <> @responder::uuid;

-- name: RejectFriendRequest :execrows
UPDATE friendships
    SET
        status = 'rejected',
        responded_at = NOW()
    WHERE
        status = 'pending' AND
        user_a_id = LEAST(@responder::uuid, @respondee::uuid) AND
        user_b_id = GREATEST(@responder::uuid, @respondee::uuid) AND
        requester_id <> @responder::uuid;

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
