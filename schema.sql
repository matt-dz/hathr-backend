CREATE TABLE users (
    id UUID DEFAULT gen_random_uuid (),
    spotify_user_id TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now (),

    PRIMARY KEY (id)
);

CREATE TABLE monthly_playlists (
    id UUID DEFAULT gen_random_uuid (),
    user_id UUID,
    tracks TEXT[] NOT NULL,
    year SMALLINT NOT NULL,
    month SMALLINT NOT NULL CHECK (month BETWEEN 1 and 12),
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now (),

    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    UNIQUE (user_id, year, month)
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
    refresh_token INT NOT NULL,

    PRIMARY KEY(user_id),
    FOREIGN KEY (user_id) REFERENCES users (spotify_user_id)
        ON DELETE CASCADE
);
