package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"

	"hathr-backend/internal/api/middleware"
	"hathr-backend/internal/database"
	hathrEnv "hathr-backend/internal/env"
	"hathr-backend/internal/logging"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5/pgxpool"
)

const defaultPort = "8080"

func main() {
	// Initialize logger
	logger := slog.New(&logging.ContextHandler{
		Handler: slog.NewTextHandler(
			os.Stderr,
			&slog.HandlerOptions{
				Level: slog.LevelDebug,
			})},
	)

	// Create database connection pool
	logger.Info("Creating database connection pool")
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

	env := hathrEnv.NewEnvironment(logger, &database.Database{Queries: database.New(pool)})
	defer env.Database.Close()

	// Create HTTP Handler
	port := os.Getenv("PORT")
	if port == "" {
		logger.Info("PORT not set, defaulting to port " + defaultPort)
		port = defaultPort
	}
	router := mux.NewRouter()
	middleware.AddRoutes(router, env)

	logger.Info("Serving at " + "0.0.0.0:" + port)
	http.Handle("/", router)
	log.Fatal(http.ListenAndServe("0.0.0.0:"+port, nil))
}
