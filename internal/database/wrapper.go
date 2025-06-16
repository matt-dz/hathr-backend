package database

import (
	"context"

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
