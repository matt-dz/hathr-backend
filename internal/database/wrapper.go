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

func NewDatabase(pool *pgxpool.Pool) *Database {
	return &Database{
		Queries: New(pool),
		pool:    pool,
	}
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
