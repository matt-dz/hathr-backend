// Package for API middleware

package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"hathr-backend/internal/api/handlers"
	hathrEnv "hathr-backend/internal/env"
	"hathr-backend/internal/logging"

	"github.com/gorilla/mux"
)

const originURL = "https://hathr.deguzman.cloud"

// Custom ResponseWriter that captures the status code
type logResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

// validateOrigin checks if the origin is in the allow list.
func validateOrigin(origin string) bool {

	if os.Getenv("ENV") == "PROD" {
		return origin == originURL
	}

	return true
}

// Handles panic recovery
func RecoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		environment, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
		if !ok {
			environment = hathrEnv.Null()
		}

		defer func() {
			if err := recover(); err != nil {
				environment.Logger.Error("Panic occurred: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()

		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

// Injects the environment object
func InjectEnvironment(env *hathrEnv.Env) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if env == nil {
				env = hathrEnv.Null()
			}
			r = r.WithContext(context.WithValue(r.Context(), hathrEnv.Key, env))
			next.ServeHTTP(w, r)
		})
	}
}

func LogRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		environment, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
		if !ok {
			environment = hathrEnv.Null()
		}

		r = r.WithContext(logging.AppendCtx(r.Context(), slog.String("method", r.Method)))
		r = r.WithContext(logging.AppendCtx(r.Context(), slog.String("path", r.URL.RequestURI())))
		lrw := &logResponseWriter{w, http.StatusOK}
		environment.Logger.InfoContext(r.Context(), "Request received")
		next.ServeHTTP(lrw, r)
		environment.Logger.LogAttrs(
			r.Context(),
			slog.LevelInfo,
			"Request completed",
			slog.Duration("duration", time.Since(start)),
			slog.Int("status", lrw.statusCode),
		)
	})
}

func HandleCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		/* If origin is not in allow list, do not add CORS headers */
		origin := r.Header.Get("Origin")
		if !validateOrigin(origin) {
			http.Error(w, "Invalid origin", http.StatusUnauthorized)
			return
		}
		w.Header().Add("Access-Control-Allow-Origin", origin)
		w.Header().Add("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Add("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding")
		w.Header().Add("Access-Control-Allow-Credentials", "true")
		w.Header().Add("Access-Control-Max-Age", "86400")
		next.ServeHTTP(w, r)
	})
}

func AddRoutes(router *mux.Router) {
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}).Methods("OPTIONS")

	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}).Methods("GET")

	router.HandleFunc("/user", handlers.UpsertUser).Methods("POST")
	router.HandleFunc("/playlists/{user_id}", handlers.GetUserPlaylists).Methods("GET")
	router.HandleFunc("/playlist/{id}", handlers.GetPlaylist).Methods("GET")
	router.HandleFunc("/playlist", handlers.CreateMonthlyPlaylist).Methods("POST")
}
