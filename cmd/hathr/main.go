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
	"github.com/jackc/pgx/v5"
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

	// Connect to DB
	logger.Info("Establishing DB Connection")
	conn, err := pgx.Connect(
		context.Background(),
		fmt.Sprintf(
			"user=%s password=%s host=%s port=%s dbname=%s sslmode=disable",
			os.Getenv("DB_USER"),
			os.Getenv("DB_PASSWORD"),
			os.Getenv("DB_HOST"),
			os.Getenv("DB_PORT"),
			os.Getenv("DB_NAME"),
		))
	if err != nil {
		panic(err)
	}

	env := hathrEnv.NewEnvironment(logger, &database.Database{Queries: database.New(conn)})
	defer env.Database.Close()

	// Create HTTP Handler
	port := os.Getenv("PORT")
	if port == "" {
		logger.Info("PORT not set, defaulting to port " + defaultPort)
		port = defaultPort
	}
	router := mux.NewRouter()
	router.Use(middleware.RecoverMiddleware)
	router.Use(middleware.InjectEnvironment(env))
	router.Use(middleware.LogRequest)
	middleware.AddRoutes(router)

	logger.Info("Serving at " + "0.0.0.0" + port)
	http.Handle("/", router)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
