// Package for environmental dependencies

package env

import (
	"hathr-backend/internal/database"
	"hathr-backend/internal/http"
	"hathr-backend/internal/logging"

	"log/slog"
)

const Key = "hathr-env"

// Holds the dependencies for the environment
type Env struct {
	Logger   *slog.Logger
	Database *database.Database
	Http     *http.Client
}

// Constructs an Env object with the provided parameters
func New(logger *slog.Logger, database *database.Database, httpclient *http.Client) *Env {
	if logger == nil {
		logger = slog.New(logging.NullLogger())
	}
	httpclient.Logger = logger

	return &Env{
		Logger:   logger,
		Database: database,
		Http:     httpclient,
	}
}

// Constructs a null instance
func Null() *Env {
	return &Env{
		Logger:   slog.New(logging.NullLogger()),
		Database: nil,
		Http:     nil,
	}
}
