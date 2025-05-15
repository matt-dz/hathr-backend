// Package for API Handlers

package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"hathr-backend/internal/api/models/responses"
	"hathr-backend/internal/database"
	hathrEnv "hathr-backend/internal/env"
	hathrJson "hathr-backend/internal/json"
	hathrJWT "hathr-backend/internal/jwt"
	hathrSpotify "hathr-backend/internal/spotify"
	spotifyErrors "hathr-backend/internal/spotify/errors"
	spotifyModels "hathr-backend/internal/spotify/models"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/zmb3/spotify/v2"
)

func Login(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	// Decode request payload
	env.Logger.DebugContext(ctx, "Decoding request body")
	var loginRequest spotifyModels.LoginRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	defer r.Body.Close()
	err := hathrJson.DecodeJson(&loginRequest, decoder)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to decode request", slog.Any("error", err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate payload
	env.Logger.DebugContext(ctx, "Validating request body")
	validate := validator.New(validator.WithRequiredStructEnabled())
	err = validate.Struct(loginRequest)
	if _, ok := err.(*validator.ValidationErrors); ok {
		env.Logger.ErrorContext(ctx, "Invalid request body", slog.Any("error", err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to validate request body", slog.Any("error", err))
		http.Error(w, "Failed to validate request body", http.StatusInternalServerError)
		return
	}

	// Login user
	loginRes, loginErr, err := hathrSpotify.LoginUser(loginRequest, env, ctx)
	if err != nil {
		http.Error(w, "Unable to login", http.StatusInternalServerError)
		return
	} else if loginErr != (spotifyErrors.LoginError{}) {
		http.Error(w, loginErr.Status, loginErr.StatusCode)
		return
	}

	// Retrieve spotify user
	spotifyUser, spotifyErr, err := hathrSpotify.GetUserProfile(r.Header.Get("Authorization"), env, ctx)
	env.Logger.DebugContext(ctx, "Retrieving user profile")
	if _, ok := err.(*url.Error); ok {
		http.Error(w, "Failed to make validation request. Try again.", http.StatusInternalServerError)
		return
	} else if errors.Is(err, hathrJson.DecodeJSONError) {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	} else if (spotifyErr != spotify.Error{}) {
		http.Error(w, spotifyErr.Message, spotifyErr.Status)
		return
	}

	// Insert user into DB
	env.Logger.DebugContext(ctx, "Upserting user")
	dbUser, err := env.Database.UpsertUser(ctx, database.UpsertUserParams{
		SpotifyUserID: spotifyUser.ID,
		Email:         spotifyUser.Email,
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to upsert user", slog.Any("error", err))
		http.Error(w, "Error inserting user into database", http.StatusInternalServerError)
		return
	}

	// Upload credentials to DB
	env.Logger.DebugContext(ctx, "Uploading credentials to DB")
	err = env.Database.UpsertSpotifyCredentials(ctx, database.UpsertSpotifyCredentialsParams{
		UserID:       spotifyUser.ID,
		AccessToken:  loginRes.AccessToken,
		TokenType:    loginRes.TokenType,
		Scope:        loginRes.Scope,
		RefreshToken: loginRes.RefreshToken,
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to upload credentials to DB", slog.Any("error", err))
		http.Error(w, "Error uploading credentials", http.StatusInternalServerError)
		return
	}

	// Retrieve private key for JWT signing
	env.Logger.DebugContext(ctx, "Retrieving private key")
	key, err := env.Database.GetLatestPrivateKey(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		env.Logger.ErrorContext(ctx, "No private key to retrieve", slog.Any("error", err))
		http.Error(w, "No private key to retrieve", http.StatusInternalServerError)
		return
	} else if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to retrieve private key", slog.Any("error", err))
		http.Error(w, "Unable to retrieve private key", http.StatusInternalServerError)
		return
	}

	// Create JWT for user
	env.Logger.DebugContext(ctx, "Creating JWT")
	signedJWT, err := hathrJWT.CreateJWT(dbUser.ID.String(), false, []byte(key.Value))
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to create JWT", slog.Any("error", err))
		http.Error(w, "Unable to create JWT", http.StatusInternalServerError)
		return
	}

	// Return JWT and refresh token
	env.Logger.DebugContext(ctx, "Encoding response")
	w.Header().Add("Authorization", fmt.Sprintf("Bearer: %s", signedJWT))
	err = json.NewEncoder(w).Encode(responses.LoginUser{
		RefreshToken: dbUser.RefreshToken.String(),
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to encode response", slog.Any("error", err))
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func CreateMonthlyPlaylist(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func GetUserPlaylists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	// Retrieve JWT
	env.Logger.DebugContext(ctx, "Retrieving JWT token from context")
	token, ok := ctx.Value("jwt").(*jwt.Token)
	if !ok {
		env.Logger.ErrorContext(ctx, "Unable to retrieve JWT token from context")
		http.Error(w, "Failed to retrieve JWT token", http.StatusInternalServerError)
		return
	}

	// Retrieve user ID from JWT
	env.Logger.DebugContext(ctx, "Retrieving user ID from JWT token")
	userID, err := token.Claims.GetSubject()
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to get subject from JWT token", slog.Any("error", err))
		http.Error(w, "Failed to get subject from JWT token", http.StatusUnauthorized)
		return
	}

	// Compare user ID from JWT with request user ID
	env.Logger.DebugContext(ctx, "Comparing user ID from JWT with request user ID")
	vars := mux.Vars(r)
	requestUserID := vars["user_id"]
	if userID != requestUserID {
		env.Logger.ErrorContext(ctx, "User ID mismatch", slog.Any("userID", userID), slog.Any("requestUserID", requestUserID))
		http.Error(w, "User ID mismatch", http.StatusForbidden)
		return
	}

	// Get user playlists
	if err := uuid.Validate(userID); err != nil { // sanity check
		env.Logger.ErrorContext(ctx, "Invalid user ID", slog.Any("error", err))
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	env.Logger.DebugContext(ctx, "Getting user playlists")
	playlists, err := env.Database.GetUserPlaylists(ctx, uuid.MustParse(userID))
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to get user playlists", slog.Any("error", err))
		http.Error(w, "Failed to get user playlists", http.StatusInternalServerError)
		return
	}

	// Serialize playlists to JSON
	env.Logger.DebugContext(ctx, "Encoding response")
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(responses.GetUserPlaylists{
		Playlists: playlists,
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to encode user playlists", slog.Any("error", err))
		http.Error(w, "Failed to encode user playlists", http.StatusInternalServerError)
		return
	}

}

func GetPlaylist(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
