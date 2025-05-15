// Package for API middleware

package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"hathr-backend/internal/api/handlers"
	hathrEnv "hathr-backend/internal/env"
	hathrJwt "hathr-backend/internal/jwt"
	"hathr-backend/internal/logging"

	"github.com/golang-jwt/jwt/v5"
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

// Logs API request
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

// Adds CORS policy
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

// Authorized request via JWT
func AuthorizeRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
		if !ok {
			env = hathrEnv.Null()
		}

		authToken := r.Header.Get("Authorization")
		rawJWT, found := strings.CutPrefix(authToken, "Bearer ")
		if !found {
			http.Error(w, "Auth token should be formatted as \"Bearer [token]\"", http.StatusUnauthorized)
		}

		env.Logger.DebugContext(r.Context(), "Validating JWT")
		token, err := hathrJwt.ValidateJWT(rawJWT)
		if err != nil {
			env.Logger.ErrorContext(r.Context(), "Invalid JWT", slog.Any("error", err))
			http.Error(w, "Invalid JWT", http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			env.Logger.ErrorContext(r.Context(), "Invalid JWT")
			http.Error(w, "Invalid JWT", http.StatusUnauthorized)
			return
		}

		env.Logger.DebugContext(r.Context(), "Checking JWT expiration")
		expiration, err := token.Claims.GetExpirationTime()
		if err != nil {
			env.Logger.ErrorContext(r.Context(), "Failed to get expiration time", slog.Any("error", err))
			http.Error(w, "Invalid exp field in JWT", http.StatusBadRequest)
			return
		}

		if expiration.Before(time.Now()) {
			http.Error(w, "Token expired", http.StatusUnauthorized)
			return
		}

		env.Logger.DebugContext(r.Context(), "Successfully validated JWT")
		r = r.WithContext(context.WithValue(r.Context(), "jwt", token))
		next.ServeHTTP(w, r)
	})
}

// Ensures admin claim is present and true in JWT
func AuthorizeAdminRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
		if !ok {
			env = hathrEnv.Null()
		}

		token, ok := r.Context().Value("jwt").(*jwt.Token)
		if !ok {
			env.Logger.ErrorContext(r.Context(), "Failed to get JWT claims")
			http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
			return
		}

		env.Logger.DebugContext(r.Context(), "Authenticating user as an admin")
		mapClaims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			env.Logger.ErrorContext(r.Context(), "Failed to get JWT claims")
			http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
			return
		}

		isAdmin, ok := mapClaims["admin"].(bool)
		if !ok {
			env.Logger.ErrorContext(r.Context(), "Failed to get admin claim")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		if !isAdmin {
			env.Logger.ErrorContext(r.Context(), "User is not an admin")
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		env.Logger.DebugContext(r.Context(), "User successfully authenticated as an admin")
		next.ServeHTTP(w, r)
	})
}

func AddRoutes(router *mux.Router) {
	s := router.PathPrefix("/api").Subrouter()
	s.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}).Methods("GET")

	s.HandleFunc("/login", handlers.Login).Methods("POST")

	playlists := s.PathPrefix("/playlists").Subrouter()
	playlists.Use(AuthorizeRequest)
	playlists.HandleFunc("/{user_id}", handlers.GetUserPlaylists).Methods("GET")
	playlists.HandleFunc("/{user_id}/{year:[0-9]+}/{month:[a-zA-z]+}", handlers.GetPlaylist).Methods("GET")

	playlist := s.PathPrefix("/playlist").Subrouter()
	playlist.Use(AuthorizeAdminRequest)
	playlist.HandleFunc("/", handlers.CreateMonthlyPlaylist).Methods("POST")
}
