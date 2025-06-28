CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TYPE role AS ENUM(
    'user',
    'admin'
);

CREATE TABLE private_keys (
    kid SERIAL,
    value TEXT NOT NULL,

    PRIMARY KEY (kid)
);

CREATE TABLE users (
    id UUID DEFAULT gen_random_uuid (),


    -- Hathr Data
    display_name TEXT,
    username TEXT UNIQUE,
    email TEXT NOT NULL,
    image_url TEXT,

    -- Spotify Data
    spotify_id TEXT UNIQUE,
    spotify_display_name TEXT,
    spotify_url TEXT,
    spotify_data JSONB,

    registered_at TIMESTAMPTZ,
    role role NOT NULL DEFAULT 'user',
    password TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now (),
    refresh_token TEXT NOT NULL,
    refresh_expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '1 year'),

    CONSTRAINT valid_admin CHECK (
        (role = 'admin' AND password IS NOT NULL AND registered_at IS NOT NULL)
        OR (role = 'user')
    ),
    CONSTRAINT valid_spotify_user CHECK (
        (spotify_id IS NOT NULL AND spotify_display_name IS NOT NULL AND spotify_url IS NOT NULL AND spotify_data IS NOT NULL)
        OR (spotify_id IS NULL AND spotify_display_name IS NULL AND spotify_url IS NULL AND spotify_data IS NULL)
    ),

    PRIMARY KEY (id)
);

CREATE INDEX n_idx ON users (id); -- Useful for pagination

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
ENUM('public', 'friends', 'private', 'unreleased');

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
    visibility playlist_visibility NOT NULL DEFAULT 'unreleased',
    image_url TEXT NOT NULL,

    year INTEGER NOT NULL,
    month INTEGER NOT NULL,
    day INTEGER NOT NULL,

    CONSTRAINT valid_month CHECK (
        month BETWEEN 1 AND 12
    ),
    CONSTRAINT valid_day CHECK (
        CASE
          WHEN type = 'weekly'  THEN day BETWEEN 1 AND 31
          WHEN type = 'monthly' THEN day = 1
          ELSE true
        END
    ),

    UNIQUE (user_id, type, year, month, day), -- Unique weekly playlists

    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE spotify_tracks (
    id TEXT NOT NULL,

    name TEXT NOT NULL,
    artists TEXT[] NOT NULL,
    popularity INTEGER NOT NULL,
    href TEXT NOT NULL,
    image_url TEXT,
    raw JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (id)
);

CREATE TABLE spotify_playlist_tracks(
    playlist_id UUID NOT NULL,
    track_id TEXT NOT NULL,
    plays INTEGER NOT NULL,

    CONSTRAINT positive_plays CHECK (plays > 0),

    PRIMARY KEY (playlist_id, track_id),
    FOREIGN KEY (playlist_id) REFERENCES playlists (id)
        ON DELETE CASCADE,
    FOREIGN KEY (track_id) REFERENCES spotify_tracks (id)
        ON DELETE CASCADE
);

CREATE TABLE spotify_tokens (
    user_id TEXT NOT NULL,
    access_token TEXT NOT NULL,
    token_type TEXT NOT NULL,
    scope TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    token_expires TIMESTAMPTZ NOT NULL,

    PRIMARY KEY(user_id),
    FOREIGN KEY (user_id) REFERENCES users (spotify_id)
        ON DELETE CASCADE
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
    href       text,
    raw        jsonb
);

CREATE TABLE invite_codes (
    code TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '1 day'),
    redeemed_by UUID,
    redeemed_at TIMESTAMPTZ,

    CONSTRAINT valid_redemption CHECK (
        (redeemed_by IS NULL AND redeemed_at IS NULL)
        OR (redeemed_by IS NOT NULL AND redeemed_at IS NOT NULL AND expires_at > redeemed_at)
    ),

    PRIMARY KEY (code),
    FOREIGN KEY (redeemed_by) REFERENCES users (id)
        ON DELETE SET NULL
);
