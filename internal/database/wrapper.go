package database

import (
	"context"

	"github.com/jackc/pgx/v5"
)

var queries *Queries
var connection *pgx.Conn

type Database struct {
	*Queries
	Conn *pgx.Conn
}

func (db *Database) Close() error {
	if db == nil {
		return nil
	}

	return db.Conn.Close(context.Background())
}
