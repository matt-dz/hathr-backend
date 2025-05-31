// Package for API middleware

package middleware

import (
	"context"
	"errors"
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

// Custom ResponseWriter that captures the status code
type logResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

// Write captures the status code and writes the response
func (lrw *logResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

// // validateOrigin checks if the origin is in the allow list.
// func validateOrigin(origin string) bool {

// 	if os.Getenv("ENV") == "PROD" {
// 		return origin == originURL
// 	}

// 	return true
// }

// Handles panic recovery
func RecoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
		if !ok {
			env = hathrEnv.Null()
		}

		defer func() {
			if err := recover(); err != nil {
				env.Logger.ErrorContext(r.Context(), "Panic occurred", slog.Any("panic", err))
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
		// /* If origin is not in allow list, do not add CORS headers */
		// origin := r.Header.Get("Origin")
		// if !validateOrigin(origin) {
		// 	http.Error(w, "Invalid origin", http.StatusUnauthorized)
		// 	return
		// }
		origin := "*"
		if os.Getenv("ENV") == "PROD" {
			origin = os.Getenv("ORIGIN_URL")
		}
		w.Header().Add("Access-Control-Allow-Origin", origin)
		w.Header().Add("Access-Control-Allow-Methods", "POST, GET, PUT, OPTIONS, DELETE")
		w.Header().Add("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization")
		w.Header().Add("Access-Control-Expose-Headers", "Authorization")
		w.Header().Add("Access-Control-Allow-Credentials", "true")
		w.Header().Add("Access-Control-Max-Age", "86400")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
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
		if errors.Is(err, jwt.ErrTokenExpired) {
			env.Logger.ErrorContext(r.Context(), "JWT expired", slog.Any("error", err))
			http.Error(w, "Access token expired", http.StatusUnauthorized)
			return
		} else if err != nil {
			env.Logger.ErrorContext(r.Context(), "Invalid JWT", slog.Any("error", err))
			http.Error(w, "Invalid JWT", http.StatusUnauthorized)
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

func MatchUserIDs(next http.Handler) http.Handler {
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

		userID, err := token.Claims.GetSubject()
		if err != nil {
			env.Logger.ErrorContext(r.Context(), "Failed to get user ID from JWT claims")
			http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
			return
		}

		if userID != mux.Vars(r)["user_id"] {
			env.Logger.ErrorContext(r.Context(), "User ID mismatch")
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		env.Logger.DebugContext(r.Context(), "User ID matched")
		next.ServeHTTP(w, r)
	})
}

func AddRoutes(router *mux.Router, env *hathrEnv.Env) {
	router.Use(HandleCORS)
	// router.Use(RecoverMiddleware)
	router.Use(InjectEnvironment(env))
	router.Use(LogRequest)

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}).Methods("OPTIONS")
	router.HandleFunc("/oauth/client-metadata.json", handlers.ServeOAuthMetadata).Methods("GET")

	s := router.PathPrefix("/api").Subrouter()
	s.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}).Methods("GET")

	s.HandleFunc("/login", handlers.Login).Methods("POST")
	s.HandleFunc("/refresh", handlers.RefreshSession).Methods("POST")

	playlists := s.PathPrefix("/me/playlists").Subrouter()
	playlists.Use(AuthorizeRequest)
	playlists.HandleFunc("", handlers.GetUserPlaylists).Methods("GET", "OPTIONS")
	playlists.HandleFunc("/{id}", handlers.GetPlaylist).Methods("GET", "OPTIONS")
	playlists.HandleFunc("/visibility/{id}", handlers.UpdateVisibility).Methods("PUT", "OPTIONS")

	playlist := s.PathPrefix("/playlist").Subrouter()
	playlist.Use(AuthorizeRequest)
	playlist.Use(AuthorizeAdminRequest)
	playlist.HandleFunc("/", handlers.CreateMonthlyPlaylist).Methods("POST")

	friendships := s.PathPrefix("/friendships").Subrouter()
	friendships.Use(AuthorizeRequest)
	friendships.HandleFunc("", handlers.ListFriends).Methods("GET", "OPTIONS")
	friendships.HandleFunc("/{id}", handlers.RemoveFriend).Methods("DELETE", "OPTIONS")

	friendRequests := s.PathPrefix("/friend-requests").Subrouter()
	friendRequests.Use(AuthorizeRequest)
	friendRequests.HandleFunc("", handlers.ListRequests).Methods("GET", "OPTIONS")
	friendRequests.HandleFunc("", handlers.CreateFriendRequest).Methods("POST", "OPTIONS")
	friendRequests.HandleFunc("/{id}", handlers.RespondToFriendRequest).Methods("PATCH", "OPTIONS")
	friendRequests.HandleFunc("/{id}", handlers.CancelFriendRequest).Methods("DELETE", "OPTIONS")

}
