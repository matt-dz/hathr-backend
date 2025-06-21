package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"hathr-backend/internal/argon2id"
	"hathr-backend/internal/database"
	"hathr-backend/internal/logging"

	"github.com/jackc/pgx/v5/pgtype"
)

func main() {
	// Initialize logger
	logger := slog.New(&logging.ContextHandler{
		Handler: slog.NewTextHandler(
			os.Stderr,
			&slog.HandlerOptions{
				Level: slog.LevelDebug,
			})},
	)

	logger.Info("Connectin to database")
	dbUrl := os.Getenv("DB_URL")
	if dbUrl == "" {
		logger.Error("DB_URL environment variable is not set")
		os.Exit(1)
	}
	logger.Debug("Creating database connection pool")
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(30*time.Second))
	defer cancel()
	db, err := database.NewDatabase(ctx, dbUrl)
	if err != nil {
		panic(err)
	}

	// Hash password
	logger.Debug("Hashing password")
	username := os.Getenv("ADMIN_USERNAME")
	password := os.Getenv("ADMIN_PASSWORD")
	email := os.Getenv("ADMIN_EMAIL")
	if username == "" || password == "" || email == "" {
		logger.Error("ADMIN_USERNAME, ADMIN_PASSWORD, and ADMIN_EMAIL environment variables must be set")
		return
	}
	passwordHash, err := argon2id.EncodeHash(password, argon2id.DefaultParams)
	if err != nil {
		logger.Error("Failed to hash password", slog.Any("error", err))
		return
	}

	// Create admin user
	logger.Debug("Creating admin user in DB")
	err = db.CreateAdminUser(context.Background(), database.CreateAdminUserParams{
		Username: pgtype.Text{
			String: username,
			Valid:  true,
		},
		Password: pgtype.Text{
			String: passwordHash,
			Valid:  true,
		},
		Email: email,
	})
	if err != nil {
		logger.Error("Failed to create admin user", slog.Any("error", err))
		return
	}
	logger.Info("Admin user created successfully", slog.String("username", username))
}
