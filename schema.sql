CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TYPE role AS ENUM(
    'user',
    'admin'
);

CREATE TABLE users (
    id UUID DEFAULT gen_random_uuid (),
    display_name TEXT,
    username TEXT UNIQUE,
    image_url TEXT,
    email TEXT NOT NULL,
    registered_at TIMESTAMPTZ,
    role role NOT NULL DEFAULT 'user',
    password TEXT,

    spotify_user_id TEXT UNIQUE,
    spotify_user_data JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now (),
    refresh_token UUID NOT NULL DEFAULT gen_random_uuid (),
    refresh_expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '1 year'),

    CONSTRAINT valid_admin CHECK (
        (role = 'admin' AND password IS NOT NULL AND registered_at IS NOT NULL)
        OR (role = 'user')
    ),
    CONSTRAINT valid_spotify_user CHECK (
        (spotify_user_id IS NOT NULL AND spotify_user_data IS NOT NULL)
        OR (spotify_user_id IS NULL AND spotify_user_data IS NULL)
    ),

    PRIMARY KEY (id)
);

CREATE INDEX users_username_trgm_gin
    ON users
    USING GIN (username gin_trgm_ops);

CREATE TYPE friendship_status AS ENUM(
    'pending',
    'accepted',
    'blocked'
);

CREATE TABLE friendships (
    user_a_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_b_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    requester_id UUID NOT NULL,

    status friendship_status NOT NULL DEFAULT 'pending',
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    responded_at TIMESTAMPTZ,
    PRIMARY KEY (user_a_id, user_b_id),

    -- enforce a single row per pair, no matter who is “first”
    CONSTRAINT canonical_form CHECK (user_a_id < user_b_id),

    -- ensure requester_id is one of the users in the friendship
    CONSTRAINT requester_is_user CHECK (user_a_id = requester_id OR user_b_id = requester_id)
);

CREATE INDEX ON friendships (user_a_id, status);
CREATE INDEX ON friendships (user_b_id, status);

CREATE TYPE playlist_visibility
AS
ENUM('public', 'friends', 'private');

CREATE TYPE playlist_type AS ENUM(
    'weekly',
    'monthly'
);

CREATE TABLE playlists (
    id UUID DEFAULT gen_random_uuid (),
    user_id UUID,
    type playlist_type NOT NULL,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now (),
    visibility playlist_visibility NOT NULL DEFAULT 'public',

    year INTEGER NOT NULL,
    week INTEGER,
    month INTEGER,

    CONSTRAINT valid_playlist CHECK (
        CASE
          WHEN type = 'weekly'  THEN week IS NOT NULL
                                  AND week BETWEEN 1 AND 52
                                  AND month IS NULL
          WHEN type = 'monthly' THEN month IS NOT NULL
                                  AND month BETWEEN 1 AND 12
                                  AND week IS NULL
          ELSE true
        END
    ),

    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    UNIQUE (user_id, type, year, week, month)
);

CREATE TABLE spotify_playlist_tracks(
    playlist_id UUID NOT NULL,
    track_id TEXT NOT NULL,

    PRIMARY KEY (playlist_id, track_id),
    FOREIGN KEY (playlist_id) REFERENCES playlists (id)
        ON DELETE CASCADE,
    FOREIGN KEY (track_id) REFERENCES spotify_tracks (id)
        ON DELETE CASCADE
);

CREATE TABLE private_keys (
    kid SERIAL,
    value TEXT NOT NULL,

    PRIMARY KEY (kid)
);

CREATE TABLE spotify_tokens (
    user_id TEXT NOT NULL,
    access_token TEXT NOT NULL,
    token_type TEXT NOT NULL,
    scope TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    token_expires TIMESTAMPTZ NOT NULL,

    PRIMARY KEY(user_id),
    FOREIGN KEY (user_id) REFERENCES users (spotify_user_id)
        ON DELETE CASCADE
);

CREATE TABLE spotify_tracks (
    id TEXT NOT NULL,

    name TEXT NOT NULL,
    artists TEXT[] NOT NULL,
    popularity INTEGER NOT NULL,
    image_url TEXT,
    raw JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (id)
);

CREATE TABLE spotify_plays (
    user_id UUID NOT NULL,
    track_id TEXT NOT NULL,
    played_at TIMESTAMPTZ NOT NULL,

    PRIMARY KEY (user_id, track_id, played_at),
    FOREIGN KEY (user_id) REFERENCES users (id)
        ON DELETE CASCADE,
    FOREIGN KEY (track_id) REFERENCES spotify_tracks (id)
        ON DELETE CASCADE
);

CREATE INDEX idx_spotify_plays_user_played_at
  ON spotify_plays (user_id, played_at);

CREATE TYPE spotify_track_input AS (
    id         text,
    name       text,
    artists    text[],
    popularity integer,
    image_url  text,
    raw        jsonb
);
