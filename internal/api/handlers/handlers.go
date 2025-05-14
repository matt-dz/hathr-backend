package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"hathr-backend/internal/api/models/requests"
	"hathr-backend/internal/api/models/responses"
	"hathr-backend/internal/database"
	hathrEnv "hathr-backend/internal/env"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/zmb3/spotify/v2"
)

const spotifyBaseURL = "https://api.spotify.com/v1/"
const bearerPrefix = "Bearer "

func UpsertUser(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	env.Logger.DebugContext(ctx, "Reading request body")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to read request body", slog.Any("error", err))
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	env.Logger.DebugContext(ctx, "Unmarshaling request body")
	var requestBody requests.UpsertUser
	err = json.Unmarshal(body, &requestBody)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to unmarshal request body", slog.Any("error", err))
		http.Error(w, "Failed to unmarshal request body", http.StatusInternalServerError)
		return
	}

	env.Logger.DebugContext(ctx, "Validating request body")
	validate := validator.New(validator.WithRequiredStructEnabled())
	err = validate.Struct(requestBody)
	if _, ok := err.(*validator.ValidationErrors); ok {
		env.Logger.ErrorContext(ctx, "Failed to validate request body", slog.Any("error", err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to validate request body", slog.Any("error", err))
		http.Error(w, "Failed to validate request body", http.StatusInternalServerError)
		return
	}

	env.Logger.DebugContext(ctx, "Creating user validation request")
	req, err := http.NewRequest(http.MethodGet, spotifyBaseURL+"me", nil)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Error while create request", slog.Any("Error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Authorization", r.Header.Get("Authorization"))

	env.Logger.DebugContext(ctx, "Sending request")
	client := http.DefaultClient
	res, err := client.Do(req)
	if _, ok := err.(*url.Error); ok {
		env.Logger.ErrorContext(ctx, "Request failed", slog.String("status", res.Status), slog.Any("error", err))
		http.Error(w, res.Status, res.StatusCode)
		return
	} else if err != nil {
		env.Logger.ErrorContext(ctx, "Request failed", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	env.Logger.DebugContext(ctx, "Reading validation response body")
	body, err = io.ReadAll(res.Body)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to read validation response", slog.Any("error", err))
		http.Error(w, "Failed to read validation response", http.StatusInternalServerError)
		return
	}

	env.Logger.DebugContext(ctx, "Unmarshaling validation response body")
	var user spotify.PrivateUser
	err = json.Unmarshal(body, &user)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to unmarshal body into user", slog.Any("error", err))
		http.Error(w, "Failed to decode validation response", http.StatusInternalServerError)
		return
	}

	env.Logger.DebugContext(ctx, "Validating credentials")
	if user.ID != requestBody.SpotifyUserID {
		env.Logger.ErrorContext(ctx, "User IDs do not match", slog.String("spotify_id", user.ID), slog.String("request id", requestBody.SpotifyUserID))
		http.Error(w, "User IDs do not match", http.StatusUnauthorized)
		return
	}

	env.Logger.DebugContext(ctx, "Upserting user")
	userID, err := env.Database.Queries.UpsertUser(ctx, database.UpsertUserParams{
		SpotifyUserID: requestBody.SpotifyUserID,
		Email:         user.Email,
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Error upserting user", slog.Any("error", err))
		http.Error(w, "Error upserting user", http.StatusInternalServerError)
		return
	}

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
