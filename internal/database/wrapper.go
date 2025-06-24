package database

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Database struct {
	*Queries
	pool *pgxpool.Pool
}

func NewDatabase(ctx context.Context, url string) (*Database, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}

	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		types, err := conn.LoadTypes(ctx, []string{"spotify_track_input", "_spotify_track_input"})
		if err != nil {
			return err
		}
		conn.TypeMap().RegisterTypes(types)
		return nil
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return &Database{
		Queries: New(pool),
		pool:    pool,
	}, nil
}

func (db *Database) Close() {
	if db == nil {
		return
	}

	db.pool.Close()
}

func (db *Database) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

const getFriendPlaylists = `-- name: GetFriendPlaylists :many
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
    u.id, u.display_name, u.username, u.image_url, u.email, u.registered_at, u.role, u.password, u.spotify_user_id, u.spotify_user_data, u.created_at, u.refresh_token, u.refresh_expires_at,
    p.id AS playlist_id,
    p.type AS playlist_type,
    p.name AS playlist_name,
    p.year AS playlist_year,
    p.month AS playlist_month,
    p.day AS playlist_day,
    p.created_at AS playlist_created_at,
    p.visibility AS playlist_visibility,
    p.image_url AS playlist_image_url,
    p.num_tracks
FROM friends fr
JOIN users u
    ON u.id = fr.friend_id
LEFT JOIN LATERAL (
    SELECT
        id, type, name, year, day,
        month, created_at, visibility,
        image_url,
        COUNT(*) as num_tracks
    FROM playlists
    JOIN spotify_playlist_tracks ppt ON ppt.playlist_id = playlists.id
    WHERE user_id = fr.friend_id AND visibility = 'public'
    GROUP BY
        id, type, name, year, month,
        day, created_at,
        visibility
    ORDER BY created_at DESC
    LIMIT 1
) p ON true
ORDER BY u.username
`

type PlaylistWithoutTracks struct {
	Day        *uint8              `json:"day"`
	Year       *uint16             `json:"year"`
	NumTracks  *uint16             `json:"num_tracks"`
	Month      *uint8              `json:"month"`
	Visibility *PlaylistVisibility `json:"visibility"`
	CreatedAt  *time.Time          `json:"created_at"`
	ID         *uuid.UUID          `json:"id"`
	Name       *string             `json:"name"`
	Type       *string             `json:"type"`
	ImageURL   *string             `json:"image_url"`
}

type GetFriendPlaylistsRow struct {
	User     User                  `json:"user"`
	Playlist PlaylistWithoutTracks `json:"playlist"`
}

func (q *Queries) GetFriendPlaylists(ctx context.Context, userAID uuid.UUID) ([]GetFriendPlaylistsRow, error) {
	rows, err := q.db.Query(ctx, getFriendPlaylists, userAID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []GetFriendPlaylistsRow
	for rows.Next() {
		var i GetFriendPlaylistsRow
		if err := rows.Scan(
			&i.User.ID,
			&i.User.DisplayName,
			&i.User.Username,
			&i.User.ImageUrl,
			&i.User.Email,
			&i.User.RegisteredAt,
			&i.User.Role,
			&i.User.Password,
			&i.User.SpotifyUserID,
			&i.User.SpotifyUserData,
			&i.User.CreatedAt,
			&i.User.RefreshToken,
			&i.User.RefreshExpiresAt,
			&i.Playlist.ID,
			&i.Playlist.Type,
			&i.Playlist.Name,
			&i.Playlist.Year,
			&i.Playlist.Month,
			&i.Playlist.Day,
			&i.Playlist.CreatedAt,
			&i.Playlist.Visibility,
			&i.Playlist.ImageURL,
			&i.Playlist.NumTracks,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}
