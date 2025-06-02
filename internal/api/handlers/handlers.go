// Package for API Handlers

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

const usernameRegex = `^[a-zA-Z0-9_.]{1,20}$`

func buildSpotifyPublicUser(spotifyUserData spotifyModels.User) spotifyModels.PublicUser {
	return spotifyModels.PublicUser{
		ID:           spotifyUserData.ID,
		DisplayName:  spotifyUserData.DisplayName,
		ExternalURLs: spotifyUserData.ExternalURLs,
		Images:       spotifyUserData.Images,
		URI:          spotifyUserData.URI,
	}
}

func buildPublicUser(user database.User, spotifyUserData spotifyModels.User) models.PublicUser {
	return models.PublicUser{
		ID:              user.ID,
		CreatedAt:       user.CreatedAt.Time,
		Username:        user.Username.String,
		DisplayName:     user.DisplayName.String,
		SpotifyUserData: buildSpotifyPublicUser(spotifyUserData),
	}
}

func listOutgoingRequests(env *hathrEnv.Env, ctx context.Context, userID uuid.UUID, w http.ResponseWriter) ([]models.FriendRequest, error) {

	response := make([]models.FriendRequest, 0)

	env.Logger.DebugContext(ctx, "Listing outgoing friend requests from DB")
	friendRequests, err := env.Database.ListOutgoingRequests(ctx, userID)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to list friend requests", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return response, err
	}

	// Process requests data
	env.Logger.DebugContext(ctx, "Processing friend requests data")
	response = make([]models.FriendRequest, len(friendRequests))
	for i, req := range friendRequests {
		var spotifyUserData spotifyModels.User
		err := json.Unmarshal(req.User.SpotifyUserData, &spotifyUserData)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Unable to unmarshal spotify user data", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return response, err
		}

		response[i] = models.FriendRequest{
			UserAID:     req.Friendship.UserAID,
			UserBID:     req.Friendship.UserBID,
			RequesterID: req.Friendship.RequesterID,
			Status:      string(req.Friendship.Status),
			RequestedAt: req.Friendship.RequestedAt.Time,
			FriendData:  buildPublicUser(req.User, spotifyUserData),
		}
	}

	return response, nil
}

func listIncomingRequests(env *hathrEnv.Env, ctx context.Context, userID uuid.UUID, w http.ResponseWriter) ([]models.FriendRequest, error) {

	response := make([]models.FriendRequest, 0)

	env.Logger.DebugContext(ctx, "Listing incoming friend requests from DB")
	friendRequests, err := env.Database.ListIncomingRequests(ctx, userID)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to list friend requests", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return response, err
	}

	// Process requests data
	env.Logger.DebugContext(ctx, "Processing friend requests data")
	response = make([]models.FriendRequest, len(friendRequests))
	for i, req := range friendRequests {
		var spotifyUserData spotifyModels.User
		err := json.Unmarshal(req.User.SpotifyUserData, &spotifyUserData)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Unable to unmarshal spotify user data", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return response, err
		}
		response[i] = models.FriendRequest{
			UserAID:     req.Friendship.UserAID,
			UserBID:     req.Friendship.UserBID,
			RequesterID: req.Friendship.RequesterID,
			Status:      string(req.Friendship.Status),
			RequestedAt: req.Friendship.RequestedAt.Time,
			FriendData:  buildPublicUser(req.User, spotifyUserData),
		}
	}

	return response, nil
}

func buildJWT(user database.User, spotifyData spotifyModels.User, key string) (string, error) {
	return hathrJWT.CreateJWT(hathrJWT.JWTParams{
		UserID:      user.ID.String(),
		Role:        string(user.Role),
		Registered:  !user.RegisteredAt.Time.IsZero(),
		Username:    user.Username.String,
		DisplayName: user.DisplayName.String,
		SpotifyData: hathrJWT.SpotifyClaims{
			DisplayName: spotifyData.DisplayName,
			Email:       spotifyData.Email,
			Images:      spotifyData.Images,
			ID:          spotifyData.ID,
		},
	}, []byte(key))
}

func ServeSpotifyOAuthMetadata(w http.ResponseWriter, r *http.Request) {
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

func SpotifyLogin(w http.ResponseWriter, r *http.Request) {

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
	var spotifyErr *spotifyErrors.SpotifyError
	env.Logger.DebugContext(ctx, "Logging in user")
	loginRes, err := hathrSpotify.LoginUser(loginRequest, env, ctx)
	if err != nil {
		http.Error(w, "Unable to login", http.StatusInternalServerError)
		return
	} else if errors.As(err, &spotifyErr) {
		http.Error(w, spotifyErr.Message, spotifyErr.StatusCode)
		return
	}
	env.Logger.DebugContext(ctx, "Successfully logged in")

	// Retrieve spotify user
	env.Logger.DebugContext(ctx, "Retrieving user profile")
	spotifyUser, err := hathrSpotify.GetUserProfile(fmt.Sprintf("Bearer %s", loginRes.AccessToken), env, ctx)
	if _, ok := err.(*url.Error); ok {
		http.Error(w, "Failed to make validation request. Try again.", http.StatusInternalServerError)
		return
	} else if errors.Is(err, hathrJson.DecodeJSONError) {
		env.Logger.ErrorContext(ctx, "Failed to decode response", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	} else if errors.As(err, &spotifyErr) {
		env.Logger.ErrorContext(ctx, "Received spotify error", slog.Any("error", spotifyErr))
		http.Error(w, spotifyErr.Message, spotifyErr.StatusCode)
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

	env.Logger.DebugContext(ctx, "Inserting user into database")
	dbUser, err := env.Database.CreateSpotifyUser(ctx, database.CreateSpotifyUserParams{
		SpotifyUserID:   spotifyUser.ID,
		Email:           spotifyUser.Email,
		SpotifyUserData: marshaledUser,
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to insert user", slog.Any("error", err))
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
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	} else if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to retrieve private key", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Create JWT for user
	env.Logger.DebugContext(ctx, "Creating JWT")
	signedJWT, err := buildJWT(dbUser, spotifyUser, key.Value)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to create JWT", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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

func CompleteSignup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	// Retrieve request parameters
	env.Logger.DebugContext(ctx, "Retrieving request parameters")
	var signupRequest requests.CompleteSignup
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	defer r.Body.Close()
	err := hathrJson.DecodeJson(&signupRequest, decoder)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to decode request", slog.Any("error", err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

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
	validator := validator.New(validator.WithRequiredStructEnabled())
	if err := validator.Struct(signupRequest); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to validate request body", slog.Any("error", err))
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	match, err := regexp.MatchString(usernameRegex, signupRequest.Username)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to validate username regex", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if !match {
		env.Logger.ErrorContext(ctx, "Invalid username", slog.String("username", signupRequest.Username))
		http.Error(w, "Invalid username", http.StatusBadRequest)
		return
	}

	if err := uuid.Validate(userID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid user ID", slog.Any("error", err))
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Update username in the database
	var pgErr *pgconn.PgError
	env.Logger.DebugContext(ctx, "Updating user in database")
	dbUser, err := env.Database.SignUpUser(ctx, database.SignUpUserParams{
		Username: pgtype.Text{
			String: signupRequest.Username,
			Valid:  true,
		},
		DisplayName: pgtype.Text{
			String: signupRequest.Username,
			Valid:  true,
		},
		ID: uuid.MustParse(userID),
	})
	if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
		env.Logger.ErrorContext(ctx, "Username taken", slog.Any("error", err))
		http.Error(w, "Username taken", http.StatusConflict)
		return
	}
	if errors.Is(err, pgx.ErrNoRows) {
		env.Logger.ErrorContext(ctx, "User not found or already registered", slog.Any("error", err))
		http.Error(w, "User not found or already registered", http.StatusNotFound)
		return
	}
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to sign up user", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Unmarshal spotify data
	env.Logger.DebugContext(ctx, "Unmarshaling spotify data")
	var spotifyUser spotifyModels.User
	err = json.Unmarshal(dbUser.SpotifyUserData, &spotifyUser)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to unmarshal spotify data", slog.Any("error", err))
		http.Error(w, "Unable to unmarshal user data", http.StatusInternalServerError)
		return
	}

	// Retrieve private key for JWT signing
	env.Logger.DebugContext(ctx, "Retrieving private key")
	key, err := env.Database.GetLatestPrivateKey(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		env.Logger.ErrorContext(ctx, "No private key to retrieve", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	} else if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to retrieve private key", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Create JWT for user
	env.Logger.DebugContext(ctx, "Creating JWT")
	signedJWT, err := buildJWT(dbUser, spotifyUser, key.Value)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to create JWT", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Return JWT
	w.Header().Add("Authorization", fmt.Sprintf("Bearer %s", signedJWT))
	w.WriteHeader(http.StatusNoContent)
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
	accessToken, err := buildJWT(user, spotifyUserData, key.Value)
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
		responseFriends[i] = buildPublicUser(f, spotifyUserData)
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

func ListRequests(w http.ResponseWriter, r *http.Request) {
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
	requestType := strings.ToLower(r.URL.Query().Get("direction"))

	if requestType != "incoming" && requestType != "outgoing" {
		env.Logger.ErrorContext(ctx, "Invalid direction", slog.String("direction", requestType))
		http.Error(w, "direction must be 'incoming' or 'outgoing'", http.StatusBadRequest)
		return
	}
	if err := uuid.Validate(userID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid user ID", slog.Any("error", err))
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// List friend requests
	var friendRequests []models.FriendRequest
	if requestType == "incoming" {
		friendRequests, err = listIncomingRequests(env, ctx, uuid.MustParse(userID), w)
	} else {
		friendRequests, err = listOutgoingRequests(env, ctx, uuid.MustParse(userID), w)
	}
	if err != nil {
		return
	}

	// Encode response
	env.Logger.DebugContext(ctx, "Encoding response")
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(responses.ListFriendRequests{
		Requests: friendRequests,
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to encode friend requests response", slog.Any("error", err))
		http.Error(w, "Failed to encode friend requests response", http.StatusInternalServerError)
		return
	}
}

func CreateFriendRequest(w http.ResponseWriter, r *http.Request) {
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
	var friendRequest requests.CreateFriendRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err = hathrJson.DecodeJson(&friendRequest, decoder)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to decode request", slog.Any("error", err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate request body
	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(friendRequest); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to validate request body", slog.Any("error", err))
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if err := uuid.Validate(userID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid user ID", slog.Any("error", err))
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Creating friend request in the database
	var pgErr *pgconn.PgError
	env.Logger.DebugContext(ctx, "Creating friend request in DB")
	rows, err := env.Database.CreateFriendRequest(ctx, database.CreateFriendRequestParams{
		Requester: uuid.MustParse(userID),
		Requestee: friendRequest.UserID,
	})

	if errors.As(err, &pgErr) {
		// foreign_key_violation - this is reached if the user tries to befriend a user that does not exist
		if pgErr.Code == "23503" {
			env.Logger.ErrorContext(ctx, "Foreign key violation - user not found", slog.Any("error", err))
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		// canonical_form violation - only way this is reached is if the user tries to befriend themselves
		if pgErr.Code == "23514" && pgErr.ConstraintName == "canonical_form" {
			env.Logger.ErrorContext(ctx, "check violation", slog.Any("error", err))
			http.Error(w, "User cannot be-friend themself", http.StatusConflict)
			return
		}
	}
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to create friend request", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if rows == 0 {
		env.Logger.ErrorContext(ctx, "No rows affected - request either already sent or users are already friends.")
		http.Error(w, "Request already sent or users are already friends", http.StatusConflict)
		return
	}

	// TODO: Send notification to the user about the friend request

	env.Logger.DebugContext(ctx, "Successfully created friend request")
	w.WriteHeader(http.StatusCreated)
}

func CancelFriendRequest(w http.ResponseWriter, r *http.Request) {
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
	friendID := mux.Vars(r)["id"]

	// Validate request parameters
	if err := uuid.Validate(userID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid user ID in JWT", slog.Any("error", err))
		http.Error(w, "Invalid user ID in JWT", http.StatusBadRequest)
		return
	}
	if err := uuid.Validate(friendID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid friend ID in route parameter", slog.Any("error", err))
		http.Error(w, "Invalid friend ID in route parameter", http.StatusBadRequest)
		return
	}

	// Remove friend request in the database
	env.Logger.DebugContext(ctx, "Removing friend request in DB")
	rows, err := env.Database.CancelFriendRequest(ctx, database.CancelFriendRequestParams{
		UserAID:     uuid.MustParse(userID),
		UserBID:     uuid.MustParse(friendID),
		RequesterID: uuid.MustParse(userID),
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to cancel friend request", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if rows == 0 {
		env.Logger.ErrorContext(ctx, "No rows affected. Friend request not found.", slog.Any("error", err))
		http.Error(w, "Outgoing friend request not found", http.StatusNotFound)
		return
	}

	env.Logger.DebugContext(ctx, "Successfully canceled friend request")
	w.WriteHeader(http.StatusNoContent)
}

func RespondToFriendRequest(w http.ResponseWriter, r *http.Request) {

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
	var friendRequest requests.ResponseToFriendRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err = hathrJson.DecodeJson(&friendRequest, decoder)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to decode request", slog.Any("error", err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate request body
	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(friendRequest); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to validate request body", slog.Any("error", err))
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if err := uuid.Validate(userID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid user ID", slog.Any("error", err))
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}
	if err := uuid.Validate(friendID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid friend ID in route parameter", slog.Any("error", err))
		http.Error(w, "Invalid friend ID in route parameter", http.StatusBadRequest)
		return
	}

	// Respond to friend request in the database
	env.Logger.DebugContext(ctx, "Updating friend request in DB")
	var rows int64
	if friendRequest.Status == "accepted" {
		rows, err = env.Database.AcceptFriendRequest(ctx, database.AcceptFriendRequestParams{
			Responder: uuid.MustParse(userID),
			Respondee: uuid.MustParse(friendID),
		})
	} else {
		rows, err = env.Database.RejectFriendRequest(ctx, database.RejectFriendRequestParams{
			Responder: uuid.MustParse(userID),
			Respondee: uuid.MustParse(friendID),
		})
	}

	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to respond to friend request", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if rows == 0 {
		env.Logger.ErrorContext(ctx, "No rows affected. Friend request not found.", slog.Any("error", err))
		http.Error(w, "Friend request not found", http.StatusNotFound)
		return
	}

	env.Logger.DebugContext(ctx, "Successfully responded to friend request")
}

func Search(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	// Retrieve request parameters
	env.Logger.DebugContext(ctx, "Retrieving request parameters")
	query := r.URL.Query().Get("q")
	if query == "" {
		env.Logger.ErrorContext(ctx, "Missing query parameter 'q'")
		http.Error(w, "Query parameter 'q' is required", http.StatusBadRequest)
		return
	}
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

	// Search for users
	env.Logger.DebugContext(ctx, "Searching for users in DB")
	dbUsers, err := env.Database.SearchUsers(ctx, database.SearchUsersParams{
		Username: query,
		ID:       uuid.MustParse(userID),
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to search users", slog.Any("error", err))
		http.Error(w, "Failed to search users", http.StatusInternalServerError)
		return
	}

	users := make([]responses.UserWithFriendshipStatus, len(dbUsers))
	for i, dbUser := range dbUsers {
		// Unmarshal spotify data
		var spotifyUserData spotifyModels.User
		err = json.Unmarshal(dbUser.User.SpotifyUserData, &spotifyUserData)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Unable to unmarshal spotify data", slog.Any("error", err))
			http.Error(w, "Unable to unmarshal user data", http.StatusInternalServerError)
			return
		}

		users[i] = responses.UserWithFriendshipStatus{
			PublicUser: models.PublicUser{
				ID:          dbUser.User.ID,
				Username:    dbUser.User.Username.String,
				DisplayName: dbUser.User.DisplayName.String,
			},
		}
		status := string(dbUser.FriendshipStatus.FriendshipStatus)
		if dbUser.FriendshipStatus.Valid {
			users[i].FriendshipStatus = &status
		} else {
			users[i].FriendshipStatus = nil
		}

		// Encode response
		env.Logger.DebugContext(ctx, "Encoding response")
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(responses.SearchUsers{
			Users: users,
		})
		if err != nil {
			env.Logger.ErrorContext(ctx, "Failed to encode search response", slog.Any("error", err))
			http.Error(w, "Failed to encode search response", http.StatusInternalServerError)
			return
		}
	}
}
