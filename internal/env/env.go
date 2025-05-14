// Package for environmental dependencies

package env

import (
	"hathr-backend/internal/database"
	"hathr-backend/internal/logging"

	"log/slog"
)

const Key = "hathr-env"

// Holds the dependencies for the environment
type Env struct {
	*slog.Logger
	Database *database.Database
}

// Constructs an Env object with the provided parameters
func NewEnvironment(logger *slog.Logger, database *database.Database) *Env {
	if logger == nil {
		logger = slog.New(logging.NullLogger())
	}

	return &Env{
		Logger:   logger,
		Database: database,
	}
}

// Constructs a null instance
func Null() *Env {
	return &Env{
		Logger:   slog.New(logging.NullLogger()),
		Database: nil,
	}
}
