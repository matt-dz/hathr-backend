-- name: CreateSpotifyUser :one
INSERT INTO users (email, spotify_id, spotify_display_name, spotify_url, spotify_data, refresh_token, image_url)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (spotify_id) DO UPDATE
    SET
        email = EXCLUDED.email,
        spotify_display_name = EXCLUDED.spotify_display_name,
        spotify_url = EXCLUDED.spotify_url,
        spotify_data = EXCLUDED.spotify_data,
        image_url = EXCLUDED.image_url
RETURNING *;

-- name: UpdateUserImage :execrows
UPDATE users
SET image_url = $1
WHERE id = $2;

-- name: GetUserBySpotifyId :one
SELECT * FROM users WHERE spotify_id = $1;

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

-- name: GetPersonalPlaylists :many
SELECT
    p.id, p.type, p.name, p.user_id,
    p.created_at, p.visibility, p.year,
    p.month, p.day, p.image_url,
    COUNT(ppt) AS num_tracks
FROM playlists p
JOIN spotify_playlist_tracks ppt
    ON ppt.playlist_id = p.id
WHERE p.user_id = $1 AND p.visibility <> 'unreleased'
GROUP BY
    p.id, p.type, p.name, p.user_id,
    p.created_at, p.visibility, p.year,
    p.month, p.day, p.image_url;

-- name: GetUserPlaylists :many
SELECT
    p.id, p.user_id, COUNT(ppt) AS num_tracks,
    p.type, p.name, p.created_at, p.visibility,
    p.year, p.month, p.day, p.image_url
FROM playlists p
JOIN spotify_playlist_tracks ppt
    ON ppt.playlist_id = p.id
JOIN users u
    ON u.id = p.user_id
LEFT JOIN friendships f
    ON (f.user_a_id = LEAST(@user_id::uuid, p.user_id) AND f.user_b_id = GREATEST(@user_id::uuid, p.user_id))
WHERE
    u.username = @username AND
    (f.status IS NULL OR f.status <> 'blocked') AND
    (p.visibility = 'public' OR
    (p.visibility = 'private' AND p.user_id = @user_id::uuid))
GROUP BY
    p.id, p.user_id,  p.type, p.name,
    p.created_at, p.visibility, p.year,
    p.month, p.day, p.image_url;

-- name: GetSpotifyPlaylistWithOwner :one
SELECT
    sqlc.embed(p),
    sqlc.embed(u)
FROM playlists p
JOIN users u
  ON u.id = p.user_id
WHERE p.id = $1;

-- name: GetSpotifyPlaylistTracks :many
SELECT
  st.id,
  st.name,
  st.artists,
  st.image_url,
  st.href
FROM spotify_playlist_tracks ppt
JOIN spotify_tracks st ON st.id = ppt.track_id
WHERE ppt.playlist_id = $1
ORDER BY ppt.plays DESC;

-- name: GetSpotifyPlaylistTrackIDs :many
SELECT st.id
FROM spotify_playlist_tracks ppt
JOIN spotify_tracks st ON st.id = ppt.track_id
WHERE ppt.playlist_id = $1
ORDER BY plays DESC;

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
  refresh_token,
  token_expires
)
VALUES (
  $1,
  $2,
  $3,
  $4,
  $5,
  $6
)
ON CONFLICT (user_id)
DO UPDATE SET
  access_token   = EXCLUDED.access_token,
  token_type     = EXCLUDED.token_type,
  scope          = EXCLUDED.scope,
  refresh_token  = EXCLUDED.refresh_token,
  token_expires = EXCLUDED.token_expires;

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
  LEAST(
    @requester_id::uuid,
    (SELECT id FROM users WHERE username = @requestee_username::text)
  ),
  GREATEST(
    @requester_id::uuid,
    (SELECT id FROM users WHERE username = @requestee_username::text)
  ),
  @requester_id::uuid,
  'pending',
  now(),
  NULL
)
RETURNING *;


-- name: DeleteFriendRequest :execrows
DELETE FROM friendships
    WHERE
        user_a_id = LEAST(
            @canceler_id::uuid,
            (SELECT id FROM users WHERE username = @cancelee_username::text)
        )
        AND user_b_id = GREATEST(
            @canceler_id::uuid,
            (SELECT id FROM users WHERE username = @cancelee_username::text)
        )
        AND status = 'pending';

-- name: AcceptFriendRequest :one
UPDATE friendships
    SET
        status = 'accepted',
        responded_at = NOW()
    WHERE
        status = 'pending'
        AND user_a_id = LEAST(
            @responder_id::uuid,
            (SELECT id FROM users WHERE username = @respondee_username::text)
        ) AND user_b_id = GREATEST(
            @responder_id::uuid,
            (SELECT id FROM users WHERE username = @respondee_username::text)
        ) AND requester_id <> @responder_id::uuid
RETURNING *;

-- name: RemoveFriendship :execrows
DELETE FROM friendships
    WHERE
        user_a_id = LEAST(
            @user_a_id::uuid,
            (SELECT id FROM users WHERE username = @user_b_username::text)
        )  AND user_b_id = GREATEST(
            @user_a_id::uuid,
            (SELECT id FROM users WHERE username = @user_b_username::text)
        ) AND status = 'accepted';

-- name: ListFriendsByID :many
SELECT u.*
FROM friendships f
JOIN users u
  ON (u.id = CASE
        WHEN f.user_a_id = $1 THEN f.user_b_id
        ELSE f.user_a_id
    END)
WHERE (f.user_a_id = LEAST($1, u.id) AND f.user_b_id = GREATEST($1, u.id))
  AND f.status = 'accepted';

-- name: ListFriendsByUsername :many
SELECT friend.*
FROM users AS me
  JOIN friendships AS f
    ON me.id IN (f.user_a_id, f.user_b_id)
  JOIN users AS friend
    ON friend.id = CASE
         WHEN me.id = f.user_a_id THEN f.user_b_id
         ELSE f.user_a_id
       END
WHERE
  me.username = $1
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

-- name: GetUserByUsername :one
SELECT u.*
FROM users u
LEFT JOIN friendships f
    ON (
    f.user_a_id = LEAST(@searcher::uuid, u.id) AND f.user_b_id = GREATEST(@searcher::uuid, u.id)
    )
WHERE u.username = @username::text AND
      (f.status IS NULL OR f.status <> 'blocked');

-- name: GetPersonalProfile :one
SELECT * FROM users WHERE id = $1;


-- name: UpdateUserProfile :one
UPDATE users
SET
  username = COALESCE($1, username),
  display_name = COALESCE($2, display_name),
  email = COALESCE(sqlc.narg('email'), email)
WHERE id = $3
RETURNING *;

-- name: CreateAdminUser :exec
INSERT INTO users (username, password, email, role, registered_at)
VALUES ($1, $2, $3, 'admin', now());

-- name: GetAdminUser :one
SELECT id, role, registered_at, refresh_token, password
FROM users
WHERE
    username = $1
    AND role = 'admin'
    AND registered_at IS NOT NULL;

-- name: UpdateSpotifyTokens :exec
UPDATE spotify_tokens s
SET
  access_token = $1,
  refresh_token = $2,
  scope = $3,
  token_expires = $4
WHERE user_id = (SELECT spotify_id FROM users WHERE id = $5);

-- name: CreateSpotifyPlay :exec
INSERT INTO spotify_plays (user_id, track_id, played_at)
VALUES ($1, $2, $3)
ON CONFLICT DO NOTHING;

-- name: GetTopSpotifyTracks :many
SELECT
    p.track_id,
    COUNT (*) AS plays
FROM spotify_plays p
WHERE
    p.user_id = @user_id::UUID
    AND p.played_at >= @start_time::TIMESTAMPTZ
    AND p.played_at < @end_time::TIMESTAMPTZ
GROUP BY p.track_id
ORDER BY plays DESC
LIMIT $1;

-- name: GetSpotifyTokens :one
SELECT
    t.access_token,
    t.refresh_token,
    t.token_expires
FROM spotify_tokens t
JOIN users u
    ON u.spotify_id = t.user_id
WHERE u.id = $1
FOR UPDATE OF t;

-- name: CreateMonthlySpotifyPlaylist :one
INSERT INTO playlists (user_id, name, type, visibility, year, month, day, image_url)
VALUES ($1, $2, 'monthly', 'unreleased', $3, $4, 1, $5)
ON CONFLICT (user_id, type, year, month) DO UPDATE
    SET month = playlists.month -- no-op
RETURNING id as playlist_id;

-- name: CreateWeeklySpotifyPlaylist :one
INSERT INTO playlists (user_id, name, type, visibility, year, month, day, image_url)
VALUES ($1, $2, 'weekly', 'unreleased', $3, $4, $5, $6)
ON CONFLICT (user_id, type, year, month, day) DO UPDATE
    SET day = playlists.day -- no-op
RETURNING id as playlist_id;

-- name: AddSpotifyPlaylistTracks :exec
INSERT INTO spotify_playlist_tracks (playlist_id, track_id, plays)
SELECT @playlist_id::UUID, u.track_ids, p.plays
FROM unnest(@track_ids::TEXT[]) WITH ORDINALITY AS u(track_ids, idx)
    JOIN unnest(@plays::INTEGER[]) WITH ORDINALITY AS p(plays, idx)
    USING (idx)
ON CONFLICT DO NOTHING;

-- name: CreateSpotifyTracks :exec
INSERT INTO spotify_tracks (
  id, name, artists, popularity,
  image_url, href, raw, updated_at
)
SELECT
  t.id,
  t.name,
  t.artists,
  t.popularity,
  t.image_url,
  t.href,
  t.raw,
  now()
FROM unnest(@tracks::spotify_track_input[]) AS t(
  id, name, artists, popularity, image_url, href, raw
)
ON CONFLICT DO NOTHING;

-- name: CreateSpotifyPlays :exec
INSERT INTO spotify_plays (user_id, track_id, played_at)
SELECT @user_id::UUID, u.ids, p.played
FROM unnest(@ids::TEXT[]) WITH ORDINALITY AS u(ids, idx)
    JOIN unnest(@played::TIMESTAMPTZ[]) WITH ORDINALITY AS p(played, idx)
    USING (idx)
ON CONFLICT DO NOTHING;

-- name: ListRegisteredUsers :many
SELECT id FROM users
WHERE
    role = 'user' AND
    registered_at IS NOT NULL AND
    id > @after::UUID
ORDER BY id ASC
LIMIT @lim::INTEGER;

-- name: ReleaseMonthlyPlaylists :execrows
UPDATE playlists
SET visibility = 'public'
WHERE
    year = $1
    AND month = $2
    AND type = 'monthly'
    AND visibility = 'unreleased';

-- name: ReleaseWeeklyPlaylists :execrows
UPDATE playlists
SET visibility = 'public'
WHERE
    year = $1
    AND month = $2
    AND day = $3
    AND type = 'weekly'
    AND visibility = 'unreleased';

-- name: GetPlaylistDateAndType :one
SELECT year, month, day, type, image_url
FROM playlists
WHERE id = $1;

-- name: GetSpotifyUserID :one
SELECT spotify_id FROM users WHERE id = $1;

-- name: CountFriends :one
SELECT COUNT(f)
FROM users AS u
JOIN friendships AS f
    ON u.id IN (f.user_a_id, f.user_b_id)
WHERE
  u.username = $1
  AND f.status = 'accepted';

-- name: GetFriendshipStatus :one
SELECT f.*
FROM friendships f
WHERE f.user_a_id = LEAST(
        (SELECT id FROM users u WHERE u.username = @username_a::text),
        (SELECT id FROM users u WHERE u.username = @username_b::text)
    )
AND f.user_b_id = GREATEST(
        (SELECT id FROM users u WHERE u.username = @username_a::text),
        (SELECT id FROM users u WHERE u.username = @username_b::text)
    );
