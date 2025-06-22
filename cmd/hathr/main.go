package main

import (
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"hathr-backend/internal/api/middleware"
	"hathr-backend/internal/database"
	hathrEnv "hathr-backend/internal/env"
	hathrHttp "hathr-backend/internal/http"
	"hathr-backend/internal/logging"

	"github.com/gorilla/mux"
	"golang.org/x/net/context"
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

	// Create db connection
	logger.Info("Connecting to database")
	dbUrl := os.Getenv("DB_URL")
	if dbUrl == "" {
		logger.Error("DB_URL environment variable is not set")
		os.Exit(1)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(30*time.Second))
	defer cancel()
	db, err := database.NewDatabase(ctx, dbUrl)
	if err != nil {
		logger.Error("Failed to create database connection pool", "error", err)
		os.Exit(1)
	}
	env := hathrEnv.New(logger, db, hathrHttp.New())
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
