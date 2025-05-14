// Package for API Handlers

package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"hathr-backend/internal/api/models/requests"
	"hathr-backend/internal/api/models/responses"
	"hathr-backend/internal/database"
	hathrEnv "hathr-backend/internal/env"
	hathrJson "hathr-backend/internal/json"
	hathrSpotify "hathr-backend/internal/spotify"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

func UpsertUser(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	// Decode request payload
	env.Logger.DebugContext(ctx, "Decoding request body")
	var requestBody requests.UpsertUser
	err := hathrJson.DecodeJson(&requestBody, r.Body)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to decode request", slog.Any("error", err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate payload
	env.Logger.DebugContext(ctx, "Validating request body")
	validate := validator.New(validator.WithRequiredStructEnabled())
	err = validate.Struct(requestBody)
	if _, ok := err.(*validator.ValidationErrors); ok {
		env.Logger.ErrorContext(ctx, "Invalid request body", slog.Any("error", err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to validate request body", slog.Any("error", err))
		http.Error(w, "Failed to validate request body", http.StatusInternalServerError)
		return
	}

	// Validate auth token
	spotifyUser, err := hathrSpotify.ValidateUserProfile(r.Header.Get("Authorization"), env, ctx)
	env.Logger.DebugContext(ctx, "Validating authorization token")
	if _, ok := err.(*url.Error); ok {
		http.Error(w, "Failed to make validation request. Try again.", http.StatusInternalServerError)
		return
	} else if errors.Is(err, hathrJson.DecodeJSONError) {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Validating IDs
	env.Logger.DebugContext(ctx, "Validating IDs")
	if spotifyUser.ID != requestBody.SpotifyUserID {
		env.Logger.ErrorContext(ctx, "User IDs do not match", slog.String("spotify_id", spotifyUser.ID), slog.String("request id", requestBody.SpotifyUserID))
		http.Error(w, "Invalid User ID", http.StatusUnauthorized)
		return
	}

	// Upsert user
	env.Logger.DebugContext(ctx, "Upserting user")
	userID, err := env.Database.Queries.UpsertUser(ctx, database.UpsertUserParams{
		SpotifyUserID: requestBody.SpotifyUserID,
		Email:         spotifyUser.Email,
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Error upserting user", slog.Any("error", err))
		http.Error(w, "Error upserting user", http.StatusInternalServerError)
		return
	}

	// Encode request
	parsedUUID, err := uuid.ParseBytes(userID.Bytes[:])
	if err != nil {
		env.Logger.ErrorContext(ctx, "Error parsing user id", slog.Any("error", err))
		http.Error(w, "Error parsing user id", http.StatusInternalServerError)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(responses.UpsertUser{ID: parsedUUID})
}

func CreateMonthlyPlaylist(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func GetUserPlaylists(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func GetPlaylist(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
