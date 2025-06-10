package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"hathr-backend/internal/argon2id"
	"hathr-backend/internal/database"
	"hathr-backend/internal/logging"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
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

	logger.Debug("Creating database connection pool")
	pool, err := pgxpool.New(
		context.Background(),
		fmt.Sprintf(
			"user=%s password=%s host=%s port=%s dbname=%s sslmode=disable",
			os.Getenv("DB_USER"),
			os.Getenv("DB_PASSWORD"),
			os.Getenv("DB_HOST"),
			os.Getenv("DB_PORT"),
			os.Getenv("DB_NAME"),
		),
	)
	if err != nil {
		panic(err)
	}

	db := &database.Database{Queries: database.New(pool)}

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
