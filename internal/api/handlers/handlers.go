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
	"time"

	"hathr-backend/internal/api/models"
	"hathr-backend/internal/api/models/requests"
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
	if err := validate.Struct(loginRequest); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to validate request body", slog.Any("error", err))
		http.Error(w, "Invalid request", http.StatusBadRequest)
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
	signedJWT, err := hathrJWT.CreateJWT(hathrJWT.JWTParams{
		UserID: dbUser.ID.String(),
		Admin:  false,
		SpotifyData: hathrJWT.SpotifyClaims{
			DisplayName: spotifyUser.DisplayName,
			Email:       spotifyUser.Email,
			Images:      spotifyUser.Images,
			ID:          spotifyUser.ID,
		},
	}, []byte(key.Value))
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to create JWT", slog.Any("error", err))
		http.Error(w, "Unable to create JWT", http.StatusInternalServerError)
		return
	}

	// Return JWT
	env.Logger.DebugContext(ctx, "Encoding response")
	w.Header().Add("Authorization", fmt.Sprintf("Bearer %s", signedJWT))
	err = json.NewEncoder(w).Encode(responses.LoginUser{
		RefreshToken: dbUser.RefreshToken,
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to encode response", slog.Any("error", err))
		http.Error(w, "Unable to encode response", http.StatusInternalServerError)
		return
	}
}

func RefreshSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	// Decode request payload
	env.Logger.DebugContext(ctx, "Decoding request body")
	var refreshRequest requests.RefreshSession
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	defer r.Body.Close()
	err := hathrJson.DecodeJson(&refreshRequest, decoder)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to decode request", slog.Any("error", err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate payload
	env.Logger.DebugContext(ctx, "Validating request body")
	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(refreshRequest); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to validate request body", slog.Any("error", err))
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Retrieve user
	env.Logger.DebugContext(ctx, "Retrieving user")
	user, err := env.Database.GetUserFromSession(ctx, refreshRequest.RefreshToken)
	if errors.Is(err, pgx.ErrNoRows) {
		env.Logger.ErrorContext(ctx, "No user associated with token", slog.Any("error", err))
		http.Error(w, "No user associated with token", http.StatusNotFound)
		return
	} else if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to retrieve user", slog.Any("error", err))
		http.Error(w, "Unable to retrieve user", http.StatusInternalServerError)
		return
	}

	// Validate refresh token
	if user.RefreshExpiresAt.Time.Before(time.Now()) {
		env.Logger.ErrorContext(ctx, "Refresh token expired")
		http.Error(w, "Refresh token expired", http.StatusUnauthorized)
		return
	}

	// Retrieve private key for JWT signing
	env.Logger.DebugContext(ctx, "Retrieving private key")
	key, err := env.Database.GetLatestPrivateKey(ctx)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to retrieve private key", slog.Any("error", err))
		http.Error(w, "Unable to retrieve private key", http.StatusInternalServerError)
		return
	}

	// Unmarshal spotify data
	env.Logger.DebugContext(ctx, "Unmarshaling spotify data")
	var spotifyUserData spotifyModels.User
	err = json.Unmarshal(user.SpotifyUserData, &spotifyUserData)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to unmarshal spotify data", slog.Any("error", err))
		http.Error(w, "Unable to unmarshal user data", http.StatusInternalServerError)
		return
	}

	// Create JWT
	env.Logger.DebugContext(ctx, "Creating JWT")
	accessToken, err := hathrJWT.CreateJWT(hathrJWT.JWTParams{
		UserID: user.ID.String(),
		Admin:  false,
		SpotifyData: hathrJWT.SpotifyClaims{
			DisplayName: spotifyUserData.DisplayName,
			Email:       spotifyUserData.Email,
			Images:      spotifyUserData.Images,
			ID:          spotifyUserData.ID,
		},
	}, []byte(key.Value))
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to create JWT", slog.Any("error", err))
		http.Error(w, "Unable to create JWT", http.StatusInternalServerError)
		return
	}

	// Encode response
	env.Logger.DebugContext(ctx, "Encoding response")
	w.Header().Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
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
	jwt, ok := ctx.Value("jwt").(*jwt.Token)
	if !ok {
		env.Logger.ErrorContext(ctx, "Failed to get JWT claims")
		http.Error(w, "JWT not found", http.StatusUnauthorized)
		return
	}
	userID, err := jwt.Claims.GetSubject()
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to get user ID from JWT claims")
		http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
		return
	}

	env.Logger.DebugContext(ctx, "Getting user playlists")
	dbPlaylists, err := env.Database.GetUserPlaylists(ctx, uuid.MustParse(userID))
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to get user playlists", slog.Any("error", err))
		http.Error(w, "Failed to get user playlists", http.StatusInternalServerError)
		return
	}

	// Decode tracks
	env.Logger.DebugContext(ctx, "Decoding tracks")
	playlists := responses.GetUserPlaylists{
		Playlists: make([]responses.MonthlyPlaylist, 0),
	}
	for _, playlist := range dbPlaylists {
		// Unmarshal each track
		tracks := make([]map[string]interface{}, 0)
		for j, t := range playlist.Tracks {
			var track map[string]interface{}
			env.Logger.DebugContext(ctx, "Unarmashaling track", slog.Int("no.", j))
			err := json.Unmarshal(t, &track)
			if err != nil {
				env.Logger.ErrorContext(ctx, "Unable to unmarshal track", slog.Any("error", err))
				http.Error(w, "Unable to unmarshal track", http.StatusInternalServerError)
				return
			}
			tracks = append(tracks, track)
		}

		month, err := models.GetMonth(int(playlist.Month))
		if err != nil {
			env.Logger.ErrorContext(ctx, "Invalid month", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		playlists.Playlists = append(playlists.Playlists, responses.MonthlyPlaylist{
			ID:         playlist.ID,
			UserID:     playlist.UserID,
			Year:       int(playlist.Year),
			Month:      month,
			Name:       playlist.Name,
			CreatedAt:  playlist.CreatedAt.Time,
			Visibility: playlist.Visibility,
			Tracks:     tracks,
		})
		env.Logger.DebugContext(ctx, "Unmarshaled tracks")
	}

	// Serialize playlists to JSON
	env.Logger.DebugContext(ctx, "Encoding response")
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(playlists)
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
	playlistID := mux.Vars(r)["id"]
	jwt, ok := ctx.Value("jwt").(*jwt.Token)
	if !ok {
		env.Logger.ErrorContext(ctx, "Failed to get JWT claims")
		http.Error(w, "JWT not found", http.StatusUnauthorized)
		return
	}
	userID, err := jwt.Claims.GetSubject()
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to get user ID from JWT claims")
		http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
		return
	}

	// Validate parameters
	env.Logger.DebugContext(ctx, "Validating parameters")
	if err := uuid.Validate(playlistID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid playlist ID", slog.Any("error", err))
		http.Error(w, "Invalid playlist ID", http.StatusBadRequest)
		return
	}
	if err := uuid.Validate(userID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid user ID", slog.Any("error", err))
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Retrieve playlist
	env.Logger.DebugContext(ctx, "Retrieving playlist")
	playlist, err := env.Database.Queries.GetPlaylist(ctx, uuid.MustParse(playlistID))
	if errors.Is(err, pgx.ErrNoRows) {
		env.Logger.ErrorContext(ctx, "Playlist not found", slog.Any("error", err))
		http.Error(w, "Playlist not found", http.StatusNotFound)
		return
	} else if err != nil {
		env.Logger.ErrorContext(ctx, "Unsuccessful query", slog.Any("error", err))
		http.Error(w, "Unable to retrieve playlist", http.StatusInternalServerError)
		return
	}

	// Check if user is authorized to view the playlist
	if playlist.UserID != uuid.MustParse(userID) &&
		playlist.Visibility != database.PlaylistVisibilityPublic {
		env.Logger.ErrorContext(ctx, "User not authorized to view playlist")
		http.Error(w, "User not authorized to view playlist", http.StatusForbidden)
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
		ID:         playlist.ID,
		Tracks:     tracks,
		Year:       int(playlist.Year),
		Month:      playlistMonth,
		Name:       playlist.Name,
		CreatedAt:  playlist.CreatedAt.Time,
		Visibility: playlist.Visibility,
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to encode response", slog.Any("error", err))
		http.Error(w, "Unable to encode response", http.StatusInternalServerError)
	}
}

func UpdateVisibility(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	// Retrieve request parameters
	env.Logger.DebugContext(ctx, "Retrieving request parameters")
	playlistID := mux.Vars(r)["id"]
	jwt, ok := ctx.Value("jwt").(*jwt.Token)
	if !ok {
		env.Logger.ErrorContext(ctx, "Failed to get JWT claims")
		http.Error(w, "JWT not found", http.StatusUnauthorized)
		return
	}
	userID, err := jwt.Claims.GetSubject()
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to get user ID from JWT claims")
		http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
		return
	}

	// Decode request
	env.Logger.DebugContext(ctx, "Decoding request body")
	var req requests.UpdateVisibility
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err = hathrJson.DecodeJson(&req, decoder)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to decode request", slog.Any("error", err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validating request body
	env.Logger.DebugContext(ctx, "Validating request body")
	validate := validator.New(validator.WithRequiredStructEnabled())
	if err = validate.Struct(req); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to validate request body", slog.Any("error", err))
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if err := uuid.Validate(playlistID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid playlist ID", slog.Any("error", err))
		http.Error(w, "Invalid playlist ID", http.StatusBadRequest)
		return
	}
	if err := uuid.Validate(userID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid user ID", slog.Any("error", err))
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Update visibility in the database
	env.Logger.DebugContext(ctx, "Updating visibility")
	rows, err := env.Database.UpdateVisibility(ctx, database.UpdateVisibilityParams{
		Visibility: req.Visibility,
		ID:         uuid.MustParse(playlistID),
		UserID:     uuid.MustParse(userID),
	})
	if rows == 0 {
		env.Logger.ErrorContext(ctx, "No rows affected. Playlist not found.", slog.Any("error", err))
		http.Error(w, "Playlist not found or you are not authorized to update it", http.StatusNotFound)
		return
	}
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to update visibility", slog.Any("error", err))
		http.Error(w, "Failed to update visibility", http.StatusInternalServerError)
		return
	}
	env.Logger.DebugContext(ctx, "Successfully updated visibility")
	w.WriteHeader(http.StatusNoContent)
}

func CreateFriendRequest(w http.ResponseWriter, r *http.Request)    {}
func DeleteFriendRequest(w http.ResponseWriter, r *http.Request)    {}
func RespondToFriendRequest(w http.ResponseWriter, r *http.Request) {}

func RemoveFriend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	// Retrieve request parameters
	env.Logger.DebugContext(ctx, "Retrieving request parameters")
	jwt, ok := ctx.Value("jwt").(*jwt.Token)
	if !ok {
		env.Logger.ErrorContext(ctx, "Failed to get JWT claims")
		http.Error(w, "JWT not found", http.StatusUnauthorized)
		return
	}
	friendID := mux.Vars(r)["id"]
	userID, err := jwt.Claims.GetSubject()
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to get user ID from JWT claims")
		http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
		return
	}

	// Validate parameters
	env.Logger.DebugContext(ctx, "Validating parameters")
	if err := uuid.Validate(friendID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid user ID", slog.Any("error", err))
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}
	if err := uuid.Validate(userID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid friend id", slog.Any("error", err))
		http.Error(w, "Invalid ID in route parameter", http.StatusBadRequest)
		return
	}

	rows, err := env.Database.RemoveFriendship(ctx, database.RemoveFriendshipParams{
		UserAID: uuid.MustParse(userID),
		UserBID: uuid.MustParse(friendID),
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to remove friendship", slog.Any("error", err))
		http.Error(w, "Failed to remove friendship", http.StatusInternalServerError)
		return
	}
	if rows == 0 {
		env.Logger.ErrorContext(ctx, "No rows affected. Friendship not found.", slog.Any("error", err))
		http.Error(w, "Friendship not found", http.StatusNotFound)
		return
	}

	env.Logger.DebugContext(ctx, "Successfully removed friendship")
	w.WriteHeader(http.StatusNoContent)
}

func ListFriends(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	// Retrieve request parameters
	env.Logger.DebugContext(ctx, "Retrieving request parameters")
	jwt, ok := ctx.Value("jwt").(*jwt.Token)
	if !ok {
		env.Logger.ErrorContext(ctx, "Failed to get JWT claims")
		http.Error(w, "JWT not found", http.StatusUnauthorized)
		return
	}
	userID, err := jwt.Claims.GetSubject()
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to get user ID from JWT claims")
		http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
		return
	}

	// Validate parameters
	env.Logger.DebugContext(ctx, "Validating parameters")
	if err := uuid.Validate(userID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid user ID", slog.Any("error", err))
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// List friends
	env.Logger.DebugContext(ctx, "Listing friends from DB")
	friends, err := env.Database.ListFriends(ctx, uuid.MustParse(userID))
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to list friends", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Process friends data
	env.Logger.DebugContext(ctx, "Processing friends data")
	responseFriends := make([]models.PublicUser, len(friends))
	for i, f := range friends {
		var spotifyUserData spotifyModels.User
		if err := json.Unmarshal(f.SpotifyUserData, &spotifyUserData); err != nil {
			env.Logger.ErrorContext(ctx, "Unable to unmarshal spotify user data", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		responseFriends[i] = models.PublicUser{
			ID:        f.ID,
			CreatedAt: f.CreatedAt.Time,
			SpotifyUserData: spotifyModels.PublicUser{
				DisplayName:  spotifyUserData.DisplayName,
				ExternalURLs: spotifyUserData.ExternalURLs,
				ID:           spotifyUserData.ID,
				Images:       spotifyUserData.Images,
				URI:          spotifyUserData.URI,
			},
		}
	}

	// Encode response
	env.Logger.DebugContext(ctx, "Encoding response")
	err = json.NewEncoder(w).Encode(responses.ListFriends{
		Friends: responseFriends,
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to encode friends response", slog.Any("error", err))
		http.Error(w, "Failed to encode friends response", http.StatusInternalServerError)
		return
	}
}
func ListRequests(w http.ResponseWriter, r *http.Request) {}
