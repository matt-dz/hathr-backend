// Package for API middleware

package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	hathrEnv "hathr-backend/internal/env"
	"hathr-backend/internal/logging"

	"github.com/gorilla/mux"
)

const envKey = "env"

// Custom ResponseWriter that captures the status code
type logResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

// Handles panic recovery
func RecoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		environment, ok := r.Context().Value(envKey).(*hathrEnv.Env)
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
			r = r.WithContext(context.WithValue(r.Context(), envKey, env))
			next.ServeHTTP(w, r)
		})
	}
}

func LogRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		environment, ok := r.Context().Value(envKey).(*hathrEnv.Env)
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

func AddRoutes(router *mux.Router) {
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}).Methods("GET")
}
