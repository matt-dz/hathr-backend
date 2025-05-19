package database

import (
	"context"

	"github.com/jackc/pgx/v5"
)

var queries *Queries
var connection *pgx.Conn

type Database struct {
	*Queries
	connection *pgx.Conn
}

func (db *Database) Close() error {
	if db == nil {
		return nil
	}

	return db.connection.Close(context.Background())
}
