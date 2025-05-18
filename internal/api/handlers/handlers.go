// Package for API Handlers

package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"hathr-backend/internal/api/models"
	"hathr-backend/internal/api/models/responses"
	"hathr-backend/internal/database"
	hathrEnv "hathr-backend/internal/env"
	hathrJson "hathr-backend/internal/json"
	hathrJWT "hathr-backend/internal/jwt"
	hathrSpotify "hathr-backend/internal/spotify"
	spotifyErrors "hathr-backend/internal/spotify/errors"
	spotifyModels "hathr-backend/internal/spotify/models"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/zmb3/spotify/v2"
)

func ServeOAuthMetadata(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	env.DebugContext(ctx, "Encoding metadata")
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"client_id":    os.Getenv("SPOTIFY_CLIENT_ID"),
		"redirect_uri": os.Getenv("SPOTIFY_REDIRECT_URI"),
		"scope":        "user-read-private user-read-email user-library-read user-top-read user-read-recently-played",
	})
}

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
	env.Logger.DebugContext(ctx, "Logging in user")
	loginRes, loginErr, err := hathrSpotify.LoginUser(loginRequest, env, ctx)
	if err != nil {
		http.Error(w, "Unable to login", http.StatusInternalServerError)
		return
	} else if loginErr != (spotifyErrors.LoginError{}) {
		http.Error(w, loginErr.Status, loginErr.StatusCode)
		return
	}
	env.Logger.DebugContext(ctx, "Successfully logged in")

	// Retrieve spotify user
	env.Logger.DebugContext(ctx, "Retrieving user profile")
	spotifyUser, spotifyErr, err := hathrSpotify.GetUserProfile(fmt.Sprintf("Bearer %s", loginRes.AccessToken), env, ctx)
	if _, ok := err.(*url.Error); ok {
		http.Error(w, "Failed to make validation request. Try again.", http.StatusInternalServerError)
		return
	} else if errors.Is(err, hathrJson.DecodeJSONError) {
		env.Logger.ErrorContext(ctx, "Failed to decode response", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	} else if (spotifyErr != spotify.Error{}) {
		env.Logger.ErrorContext(ctx, "Received spotify error", slog.Any("error", spotifyErr))
		http.Error(w, spotifyErr.Message, spotifyErr.Status)
		return
	} else if err != nil {
		env.Logger.ErrorContext(ctx, "Failed request", slog.Any("error", err))
		http.Error(w, "Unable to retrieve user profile", http.StatusInternalServerError)
		return
	}

	// Insert user into DB
	env.Logger.DebugContext(ctx, "Marshaling user data")
	marshaledUser, err := json.Marshal(spotifyUser)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to marshal user data", slog.Any("error", err))
		http.Error(w, "Unable to marshal user data", http.StatusInternalServerError)
		return
	}
	env.Logger.DebugContext(ctx, "Upserting user")
	dbUser, err := env.Database.UpsertUser(ctx, database.UpsertUserParams{
		SpotifyUserID:   spotifyUser.ID,
		Email:           spotifyUser.Email,
		SpotifyUserData: marshaledUser,
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

	// Return JWT
	env.Logger.DebugContext(ctx, "Encoding response")
	w.Header().Add("Authorization", fmt.Sprintf("Bearer %s", signedJWT))
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

	// Get user playlists
	userID := mux.Vars(r)["user_id"]
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
	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	// Retrieve request parameters
	env.Logger.DebugContext(ctx, "Retrieving request parameters")
	userID, requestMonth := mux.Vars(r)["user_id"], mux.Vars(r)["month"]
	year, err := strconv.Atoi(mux.Vars(r)["year"])
	if err != nil {
		env.ErrorContext(ctx, "Cannot convert year to integer", slog.Any("error", err))
		http.Error(w, "Invalid year", http.StatusBadRequest)
		return
	}

	// Validate parameters
	env.Logger.DebugContext(ctx, "Validating parameters")
	if int(int16(year)) != year {
		env.ErrorContext(ctx, "Year is too large")
		http.Error(w, "Year is too large", http.StatusBadRequest)
		return
	}
	month := models.Month(requestMonth)
	if err := month.Validate(); err != nil {
		env.ErrorContext(ctx, "Invalid month", slog.Any("error", err))
		http.Error(w, "Invalid month: "+requestMonth, http.StatusBadRequest)
		return
	}
	if err := uuid.Validate(userID); err != nil {
		env.ErrorContext(ctx, "Invalid userID", slog.Any("error", err))
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Retrieve playlist
	env.Logger.DebugContext(ctx, "Retrieving playlist")
	playlist, err := env.Database.Queries.GetPlaylist(ctx, database.GetPlaylistParams{
		UserID: uuid.MustParse(userID),
		Year:   int16(year),
		Month:  int16(month.Index()),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		env.ErrorContext(ctx, "No playlist found", slog.Any("error", err))
		http.Error(w, "No playlist found", http.StatusNotFound)
		return
	} else if err != nil {
		env.ErrorContext(ctx, "Unsuccessful query", slog.Any("error", err))
		http.Error(w, "Unable to retrieve playlist", http.StatusInternalServerError)
		return
	}

	// Unmarshal tracks
	env.Logger.DebugContext(ctx, "Unmarshaling tracks")
	var tracks []map[string]interface{}
	for _, t := range playlist.Tracks {
		var track map[string]interface{}
		err = json.Unmarshal(t, &track)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Unable to unmarshal track", slog.Any("error", err))
			http.Error(w, "Unable to unmarshal track", http.StatusInternalServerError)
			return
		}
		tracks = append(tracks, track)
	}

	// Encoding response
	env.Logger.DebugContext(ctx, "Encoding response")
	playlistMonth, err := models.GetMonth(int(playlist.Month))
	if err != nil {
		env.Logger.ErrorContext(ctx, "Invalid month", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(responses.GetPlaylist{
		ID:        playlist.ID,
		Tracks:    tracks,
		Year:      int(playlist.Year),
		Month:     playlistMonth,
		Name:      playlist.Name,
		CreatedAt: playlist.CreatedAt.Time,
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to encode response", slog.Any("error", err))
		http.Error(w, "Unable to encode response", http.StatusInternalServerError)
	}
}
