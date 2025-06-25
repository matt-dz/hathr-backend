// Package for API Handlers

package handlers

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"hathr-backend/internal/api/models"
	"hathr-backend/internal/api/models/requests"
	"hathr-backend/internal/api/models/responses"
	"hathr-backend/internal/argon2id"
	"hathr-backend/internal/covers"
	"hathr-backend/internal/database"
	hathrEnv "hathr-backend/internal/env"
	hathrHttp "hathr-backend/internal/http"
	hathrJson "hathr-backend/internal/json"
	hathrJWT "hathr-backend/internal/jwt"
	hathrSpotify "hathr-backend/internal/spotify"
	spotifyModels "hathr-backend/internal/spotify/models"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

const usernameLength = 20
const displayNameLength = 50

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_.]{1,20}$`)
var displayNameRegex = regexp.MustCompile(`^.{1,50}$`)

func formatWeeklyPlaylistName(year uint16, month, day uint8) string {
	return fmt.Sprintf("%d/%d/%d", month, day, year)
}

func formatMonthlyPlaylistName(month models.Month, year uint16) string {
	return fmt.Sprintf("%s %d", string(month), year)
}

func buildSpotifyPublicUser(spotifyUserData spotifyModels.User) spotifyModels.PublicUser {
	return spotifyModels.PublicUser{
		ID:           spotifyUserData.ID,
		DisplayName:  spotifyUserData.DisplayName,
		ExternalURLs: spotifyUserData.ExternalURLs,
		Images:       spotifyUserData.Images,
		URI:          spotifyUserData.URI,
	}
}

func buildPublicUser(user database.User) (models.PublicUser, error) {
	var response models.PublicUser
	var spotifyUserData spotifyModels.User
	if err := json.Unmarshal(user.SpotifyUserData, &spotifyUserData); err != nil {
		return response, err
	}

	spotifyData := buildSpotifyPublicUser(spotifyUserData)
	response = models.PublicUser{
		ID:              user.ID,
		CreatedAt:       user.CreatedAt.Time,
		Username:        user.Username.String,
		ImageURL:        nil,
		DisplayName:     user.DisplayName.String,
		SpotifyUserData: &spotifyData,
	}
	if user.ImageUrl.Valid {
		response.ImageURL = &user.ImageUrl.String
	}
	return response, nil
}

func buildUserProfile(user database.User) (models.UserProfile, error) {
	var response models.UserProfile
	var spotifyUserData spotifyModels.User
	if err := json.Unmarshal(user.SpotifyUserData, &spotifyUserData); err != nil {
		return response, err
	}

	spotifyData := buildSpotifyPublicUser(spotifyUserData)
	response = models.UserProfile{
		ID:              user.ID,
		CreatedAt:       user.CreatedAt.Time,
		Username:        user.Username.String,
		Email:           user.Email,
		ImageURL:        nil,
		DisplayName:     user.DisplayName.String,
		SpotifyUserData: &spotifyData,
	}
	if user.ImageUrl.Valid {
		response.ImageURL = &user.ImageUrl.String
	}
	return response, nil
}

func copyOutgoingRequeststoFriendRequest(row []database.ListOutgoingRequestsRow) ([]models.FriendRequest, error) {
	response := make([]models.FriendRequest, len(row))
	for i, v := range row {
		user, err := buildPublicUser(v.User)
		if err != nil {
			return response, err
		}

		response[i] = models.FriendRequest{
			Friendship: v.Friendship,
			User:       user,
		}
	}
	return response, nil
}

func copyIncomingRequeststoFriendRequest(row []database.ListIncomingRequestsRow) ([]models.FriendRequest, error) {
	response := make([]models.FriendRequest, len(row))
	for i, v := range row {
		user, err := buildPublicUser(v.User)
		if err != nil {
			return response, err
		}

		response[i] = models.FriendRequest{
			Friendship: v.Friendship,
			User:       user,
		}
	}
	return response, nil
}

func copyRequeststoFriendRequest(row []database.ListRequestsRow) ([]models.FriendRequest, error) {
	response := make([]models.FriendRequest, len(row))
	for i, v := range row {
		user, err := buildPublicUser(v.User)
		if err != nil {
			return response, err
		}

		response[i] = models.FriendRequest{
			Friendship: v.Friendship,
			User:       user,
		}
	}
	return response, nil
}

func buildJWT(userID uuid.UUID, role database.Role, registered bool, key string) (string, error) {
	return hathrJWT.CreateJWT(hathrJWT.JWTParams{
		UserID:     userID.String(),
		Role:       string(role),
		Registered: registered,
	}, []byte(key))
}

func extractLargestImage(images []spotifyModels.Image) string {
	if len(images) == 0 {
		return ""
	}

	largestImage := images[0]
	largestSize := largestImage.Height
	for _, image := range images {
		if image.Height > largestSize {
			largestImage = image
			largestSize = image.Height
		}
	}
	return largestImage.URL
}

func retrieveSpotifyToken(userID uuid.UUID, env *hathrEnv.Env, ctx context.Context) (string, error) {
	tx, err := env.Database.Begin(ctx)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to begin transaction", slog.Any("error", err))
		return "", err
	}
	defer tx.Rollback(ctx)
	qx := env.Database.WithTx(tx)

	env.Logger.DebugContext(ctx, "Retrieving spotify tokens")
	tokens, err := qx.GetSpotifyTokens(ctx, userID)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to retrieve spotify tokens", slog.Any("error", err))
		return "", err
	}

	// If token expires before 1 minute, refresh it
	if tokens.TokenExpires.Time.After(time.Now().Add(time.Minute)) {
		return tokens.AccessToken, nil
	}

	// Refresh token
	env.Logger.DebugContext(ctx, "Refreshing access token", slog.Time("expires", tokens.TokenExpires.Time))
	res, err := hathrSpotify.RefreshToken(tokens.RefreshToken, env, ctx)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to refresh spotify token", slog.Any("error", err))
		return "", err
	}

	// Update token in the database
	env.Logger.DebugContext(ctx, "Updating spotify tokens in DB")
	params := database.UpdateSpotifyTokensParams{
		AccessToken:  res.AccessToken,
		Scope:        res.Scope,
		ID:           userID,
		RefreshToken: tokens.RefreshToken,
		TokenExpires: pgtype.Timestamptz{
			Time:  time.Now().Add(time.Duration(res.ExpiresIn) * time.Second),
			Valid: true,
		},
	}
	if res.RefreshToken != nil {
		params.RefreshToken = *res.RefreshToken
	}
	if err := qx.UpdateSpotifyTokens(ctx, params); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to update spotify tokens in DB", slog.Any("error", err))
		return "", err
	}

	env.Logger.DebugContext(ctx, "Committing transaction")
	if err := tx.Commit(ctx); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to commit transaction", slog.Any("error", err))
		return "", err
	}

	env.Logger.DebugContext(ctx, "Successfully refreshed spotify token")
	return res.AccessToken, nil
}

func loadDate(year int, month time.Month, day, hour, min, sec, nsec int) (time.Time, error) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		return time.Time{}, err
	}
	return time.Date(year, month, day, hour, min, sec, nsec, loc), nil
}

func validateUsername(username string) error {
	if len(username) == 0 || len(username) > usernameLength {
		return fmt.Errorf("Username must be between 1 and 20 characters.")
	}

	if match := usernameRegex.MatchString(username); !match {
		return fmt.Errorf("Username may only include alphanumeric characters, underscores, and periods.")
	}
	return nil
}

func validateDisplayName(displayName string) error {
	if len(displayName) == 0 || len(displayName) > displayNameLength {
		return fmt.Errorf("Display name must be between 1 and 50 characters.")
	}

	if !displayNameRegex.MatchString(displayName) {
		return fmt.Errorf("Display name may not include newlines.")
	}
	return nil
}

func ServeSpotifyOAuthMetadata(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	env.Logger.DebugContext(ctx, "Encoding metadata")
	w.Header().Add("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(map[string]string{
		"client_id":    os.Getenv("SPOTIFY_CLIENT_ID"),
		"redirect_uri": os.Getenv("SPOTIFY_REDIRECT_URI"),
		"scope":        "user-read-private user-read-email user-library-read user-top-read user-read-recently-played playlist-modify-public playlist-modify-private ugc-image-upload",
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to encode metadata", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func AdminLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	// Decode request payload
	env.Logger.DebugContext(ctx, "Decoding request body")
	var loginRequest requests.AdminLogin
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err := hathrJson.DecodeJson(&loginRequest, decoder)
	defer r.Body.Close()
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to decode request", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Validate payload
	env.Logger.DebugContext(ctx, "Validating request body")
	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(loginRequest); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to validate request body", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Login admin
	env.Logger.DebugContext(ctx, "Retrieving user from DB")
	user, err := env.Database.GetAdminUser(ctx,
		pgtype.Text{
			String: loginRequest.Username,
			Valid:  true,
		})

	if errors.Is(err, pgx.ErrNoRows) {
		env.Logger.ErrorContext(ctx, "Unable to get user. Invalid credentials", slog.Any("error", err))
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	} else if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to login admin", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Decode password hash
	env.Logger.DebugContext(ctx, "Decoding password hash")
	argonParams, salt, trueHash, err := argon2id.DecodeHash(user.Password.String)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to decode password hash", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Hash given password
	env.Logger.DebugContext(ctx, "Hashing given password")
	givenHash := argon2id.HashWithSalt(loginRequest.Password, *argonParams, salt)

	// Compare hashes
	env.Logger.DebugContext(ctx, "Comparing hashes")
	if subtle.ConstantTimeCompare(givenHash, trueHash) == 0 {
		env.Logger.ErrorContext(ctx, "Invalid credentials", slog.String("username", loginRequest.Username))
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	env.Logger.DebugContext(ctx, "Successfully logged in admin")

	// Retrieve private key for JWT signing
	env.Logger.DebugContext(ctx, "Retrieving private key")
	key, err := env.Database.GetLatestPrivateKey(ctx)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to retrieve private key", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Create JWT for user
	env.Logger.DebugContext(ctx, "Creating JWT")
	signedJWT, err := buildJWT(user.ID, user.Role, user.RegisteredAt.Valid, key.Value)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to create JWT", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Return JWT
	env.Logger.DebugContext(ctx, "Encoding response")
	w.Header().Add("Authorization", fmt.Sprintf("Bearer %s", signedJWT))
	err = json.NewEncoder(w).Encode(responses.LoginUser{
		RefreshToken: user.RefreshToken,
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to encode response", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
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
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Validate payload
	env.Logger.DebugContext(ctx, "Validating request body")
	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(loginRequest); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to validate request body", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Login user
	env.Logger.DebugContext(ctx, "Logging in user")
	loginRes, err := hathrSpotify.LoginUser(loginRequest, env, ctx)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to login user", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	env.Logger.DebugContext(ctx, "Successfully logged in")

	// Retrieve spotify user
	env.Logger.DebugContext(ctx, "Retrieving user profile")
	spotifyUser, err := hathrSpotify.GetUserProfile(fmt.Sprintf("Bearer %s", loginRes.AccessToken), env, ctx)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed request", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Insert user into DB
	env.Logger.DebugContext(ctx, "Marshaling user data")
	marshaledUser, err := json.Marshal(spotifyUser)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to marshal user data", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	env.Logger.DebugContext(ctx, "Inserting user into database")
	dbUser, err := env.Database.CreateSpotifyUser(ctx, database.CreateSpotifyUserParams{
		SpotifyUserID: pgtype.Text{
			String: spotifyUser.ID,
			Valid:  true,
		},
		Email:           spotifyUser.Email,
		SpotifyUserData: marshaledUser,
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to insert user", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
		TokenExpires: pgtype.Timestamptz{
			Time:  time.Now().Add(time.Duration(loginRes.ExpiresIn) * time.Second),
			Valid: true,
		},
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to upload credentials to DB", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Update user imageURL
	imageURL := extractLargestImage(spotifyUser.Images)
	if imageURL != "" {
		env.Logger.DebugContext(ctx, "Updating user image")
		rows, err := env.Database.UpdateUserImage(ctx, database.UpdateUserImageParams{
			ID: dbUser.ID,
			ImageUrl: pgtype.Text{
				String: imageURL,
				Valid:  true,
			},
		})
		if err != nil {
			env.Logger.ErrorContext(ctx, "Unable to update user image", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		} else if rows == 0 {
			// sanity check - this shouldn't be possible
			env.Logger.ErrorContext(ctx, "No rows updated when updating user image", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}

	// Retrieve private key for JWT signing
	env.Logger.DebugContext(ctx, "Retrieving private key")
	key, err := env.Database.GetLatestPrivateKey(ctx)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to retrieve private key", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Create JWT for user
	env.Logger.DebugContext(ctx, "Creating JWT")
	signedJWT, err := buildJWT(dbUser.ID, dbUser.Role, dbUser.RegisteredAt.Valid, key.Value)
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
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
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
	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(signupRequest); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to validate request body", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if err := validateUsername(signupRequest.Username); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid username", slog.String("username", signupRequest.Username))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := uuid.Validate(userID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid ID in JWT", slog.Any("error", err))
		http.Error(w, "Invalid ID in JWT", http.StatusBadRequest)
		return
	}

	// Update username in the database
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
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
		env.Logger.ErrorContext(ctx, "Username taken", slog.Any("error", err))
		http.Error(w, "Username unavailable", http.StatusConflict)
		return
	}
	if errors.Is(err, pgx.ErrNoRows) {
		env.Logger.ErrorContext(ctx, "User not found or already registered", slog.Any("error", err))
		http.Error(w, "User not found", http.StatusNotFound)
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
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
	signedJWT, err := buildJWT(dbUser.ID, dbUser.Role, dbUser.RegisteredAt.Valid, key.Value)
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
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Validate payload
	env.Logger.DebugContext(ctx, "Validating request body")
	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(refreshRequest); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to validate request body", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
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
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Unmarshal spotify data
	env.Logger.DebugContext(ctx, "Unmarshaling spotify data")
	var spotifyUserData spotifyModels.User
	err = json.Unmarshal(user.SpotifyUserData, &spotifyUserData)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to unmarshal spotify data", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Create JWT
	env.Logger.DebugContext(ctx, "Creating JWT")
	accessToken, err := buildJWT(user.ID, user.Role, user.RegisteredAt.Valid, key.Value)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to create JWT", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Encode response
	env.Logger.DebugContext(ctx, "Encoding response")
	w.Header().Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
}

func CreateSpotifyPlaylist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	// Decode request payload
	userID := mux.Vars(r)["user_id"]
	var request requests.CreatePlaylist
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	defer r.Body.Close()
	if err := hathrJson.DecodeJson(&request, decoder); err != nil {
		env.Logger.ErrorContext(ctx, "Unable to decode request", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Validate payload
	env.Logger.DebugContext(ctx, "Validating parameters")
	validate := validator.New()
	if err := validate.Struct(request); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to validate request body", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if err := request.Month.Validate(); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid month", slog.Any("error", err))
		http.Error(w, "Invalid month", http.StatusBadRequest)
		return
	}

	if request.Type == "weekly" && (request.Day < 1 || request.Day > 31) {
		env.Logger.ErrorContext(ctx, "Invalid day", slog.Int("day", int(request.Day)))
		http.Error(w, "Invalid day", http.StatusBadRequest)
		return
	}

	if err := uuid.Validate(userID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid user ID", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Get time bounds
	var startDate time.Time
	var endDate time.Time
	month := time.Month(request.Month.Index() + 1)
	if request.Type == "monthly" {
		startDate, err := loadDate(int(request.Year), month, 1, 0, 0, 0, 0)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Failed to create start date", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		endDate = startDate.AddDate(0, 1, -1)
	} else if request.Type == "weekly" {
		startDate, err := loadDate(int(request.Year), month, int(request.Day), int(request.Hour), 0, 0, 0)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Failed to create start date", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		endDate = startDate.AddDate(0, 0, 7)
	}
	env.Logger.DebugContext(ctx, "Getting top songs from DB")
	tracks, err := env.Database.GetTopSpotifyTracks(ctx, database.GetTopSpotifyTracksParams{
		Limit:  50,
		UserID: uuid.MustParse(userID),
		StartTime: pgtype.Timestamptz{
			Time:  startDate,
			Valid: true,
		},
		EndTime: pgtype.Timestamptz{
			Time:  endDate,
			Valid: true,
		},
	})

	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to get top tracks from DB", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if len(tracks) == 0 {
		env.Logger.DebugContext(ctx, "No recently listened to tracks. Not creating a playlist")
		http.Error(w, "No recently listened to tracks", http.StatusConflict)
		return
	}

	// Create playlist
	var playlistID uuid.UUID
	var imageUrl string
	if request.Type == "weekly" {
		env.Logger.DebugContext(ctx, "Creating weekly playlist in DB")
		imageUrl, err = covers.WeeklyPlaylistCoverURL(request.Month, request.Year, request.Day)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Failed to generate playlist cover url", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		playlistID, err = env.Database.CreateWeeklySpotifyPlaylist(ctx, database.CreateWeeklySpotifyPlaylistParams{
			UserID:   uuid.MustParse(userID),
			Name:     formatWeeklyPlaylistName(request.Year, uint8(month), request.Day),
			Year:     int32(request.Year),
			Month:    int32(month),
			Day:      int32(request.Day),
			ImageUrl: imageUrl,
		})
	} else if request.Type == "monthly" {
		env.Logger.DebugContext(ctx, "Creating monthly playlist in DB")
		imageUrl, err = covers.MonthlyPlaylistCoverURL(request.Month, request.Year)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Failed to generate playlist cover url", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		playlistID, err = env.Database.CreateMonthlySpotifyPlaylist(ctx, database.CreateMonthlySpotifyPlaylistParams{
			UserID:   uuid.MustParse(userID),
			Name:     formatMonthlyPlaylistName(request.Month, request.Year),
			Year:     int32(request.Year),
			Month:    int32(month),
			ImageUrl: imageUrl,
		})
	}
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to create playlist in DB", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Add tracks
	env.Logger.DebugContext(ctx, "Adding tracks to playlist in DB")
	trackIDs := make([]string, len(tracks))
	for i, track := range tracks {
		trackIDs[i] = track.TrackID
	}
	err = env.Database.AddSpotifyPlaylistTracks(ctx, database.AddSpotifyPlaylistTracksParams{
		PlaylistID: playlistID,
		TrackIds:   trackIDs,
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to add tracks to playlist in DB", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Write response
	env.Logger.DebugContext(ctx, "Encoding response")
	w.WriteHeader(http.StatusCreated)
}

func GetPersonalPlaylists(w http.ResponseWriter, r *http.Request) {
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
	dbPlaylists, err := env.Database.GetPersonalPlaylists(ctx, uuid.MustParse(userID))
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to get user playlists", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Build response
	env.Logger.DebugContext(ctx, "Building response")
	response := responses.GetUserPlaylists{
		Playlists: make([]models.PlaylistWithoutTracks, len(dbPlaylists)),
	}
	for i, dbPlaylist := range dbPlaylists {
		response.Playlists[i] = models.PlaylistWithoutTracks{
			Day:        uint8(dbPlaylist.Day),
			Year:       uint16(dbPlaylist.Year),
			NumTracks:  uint16(dbPlaylist.NumTracks),
			Visibility: dbPlaylist.Visibility,
			CreatedAt:  dbPlaylist.CreatedAt.Time,
			ID:         dbPlaylist.ID,
			UserID:     dbPlaylist.UserID,
			Name:       dbPlaylist.Name,
			Type:       string(dbPlaylist.Type),
			ImageURL:   dbPlaylist.ImageUrl,
		}

		month, err := models.GetMonth(int(dbPlaylist.Month))
		if err != nil {
			env.Logger.ErrorContext(ctx, "Invalid month in playlist", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		response.Playlists[i].Month = month
	}

	// Encode playlists
	env.Logger.DebugContext(ctx, "Encoding response")
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to encode user playlists", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
		env.Logger.ErrorContext(ctx, "Invalid ID in JWT", slog.Any("error", err))
		http.Error(w, "Invalid ID in JWT", http.StatusBadRequest)
		return
	}

	// Retrieve playlist
	env.Logger.DebugContext(ctx, "Retrieving playlist")
	dbPlaylist, err := env.Database.Queries.GetSpotifyPlaylistWithOwner(ctx, uuid.MustParse(playlistID))
	if errors.Is(err, pgx.ErrNoRows) {
		env.Logger.ErrorContext(ctx, "Playlist not found", slog.Any("error", err))
		http.Error(w, "Playlist not found", http.StatusNotFound)
		return
	} else if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to retrieve playlist from DB", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Check if user is authorized to view the playlist
	if (dbPlaylist.User.ID != uuid.MustParse(userID) &&
		dbPlaylist.Playlist.Visibility != database.PlaylistVisibilityPublic) || dbPlaylist.Playlist.Visibility == database.PlaylistVisibilityUnreleased {
		env.Logger.ErrorContext(ctx, "User not authorized to view playlist")
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	}

	// Fetch tracks for the playlist
	env.Logger.DebugContext(ctx, "Fetching tracks for the playlist")
	tracks, err := env.Database.GetSpotifyPlaylistTracks(ctx, dbPlaylist.Playlist.ID)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to fetch tracks from DB", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Build playlist response
	env.Logger.DebugContext(ctx, "Building playlist response")
	playlist := models.SpotifyPlaylist{
		Day:        uint8(dbPlaylist.Playlist.Day),
		Year:       uint16(dbPlaylist.Playlist.Year),
		Visibility: dbPlaylist.Playlist.Visibility,
		CreatedAt:  dbPlaylist.Playlist.CreatedAt.Time,
		Tracks:     make([]models.SpotifyPlaylistTrack, len(tracks)),
		ID:         dbPlaylist.Playlist.ID,
		UserID:     dbPlaylist.Playlist.UserID,
		Name:       dbPlaylist.Playlist.Name,
		Type:       string(dbPlaylist.Playlist.Type),
		ImageURL:   dbPlaylist.Playlist.ImageUrl,
	}

	month, err := models.GetMonth(int(dbPlaylist.Playlist.Month))
	if err != nil {
		env.Logger.ErrorContext(ctx, "Invalid month in playlist", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	playlist.Month = month

	for i, track := range tracks {
		playlist.Tracks[i] = models.SpotifyPlaylistTrack{
			ID:       track.ID,
			Name:     track.Name,
			Artists:  track.Artists,
			ImageURL: track.ImageUrl.String,
			Href:     track.Href,
		}
	}

	// Unmarshal spotify user data
	env.Logger.DebugContext(ctx, "Unmarshaling spotify user data")
	user, err := buildPublicUser(dbPlaylist.User)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Error building user", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Encoding response
	env.Logger.DebugContext(ctx, "Encoding response")
	w.Header().Add("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(responses.GetPlaylist{
		Playlist: playlist,
		User:     user,
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to encode response", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
	defer r.Body.Close()
	err = hathrJson.DecodeJson(&req, decoder)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to decode request", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Validating request body
	env.Logger.DebugContext(ctx, "Validating request body")
	validate := validator.New(validator.WithRequiredStructEnabled())
	if err = validate.Struct(req); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to validate request body", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if err := uuid.Validate(playlistID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid playlist ID", slog.Any("error", err))
		http.Error(w, "Invalid playlist ID", http.StatusBadRequest)
		return
	}
	if err := uuid.Validate(userID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid ID in JWT", slog.Any("error", err))
		http.Error(w, "Invalid ID in JWT", http.StatusBadRequest)
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
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	env.Logger.DebugContext(ctx, "Successfully updated visibility")
	w.WriteHeader(http.StatusNoContent)
}

func CountFriends(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	// Retrieve request parameters
	username := mux.Vars(r)["username"]

	// Retrieve friend count
	env.Logger.DebugContext(ctx, "Retrieving friend count from DB")
	friends, err := env.Database.CountFriends(ctx, pgtype.Text{String: username, Valid: true})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to retrieve friend count", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Build response
	env.Logger.DebugContext(ctx, "Building response")
	w.Header().Add("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(responses.CountFriends{Count: uint(friends)})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to build response", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func AreFriends(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	// Retrieve request parameters
	env.Logger.DebugContext(ctx, "Retrieving request paramters")
	usernameA := r.URL.Query().Get("username_a")
	usernameB := r.URL.Query().Get("username_b")

	// Check db for friendship
	env.Logger.DebugContext(ctx, "Checking if friendship exists in DB")
	areFriends, err := env.Database.AreFriends(ctx, database.AreFriendsParams{
		UsernameA: usernameA,
		UsernameB: usernameB,
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Query failed", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Build response
	env.Logger.DebugContext(ctx, "Building response")
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(responses.AreFriends{AreFriends: areFriends})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to encode response", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
	friendID := mux.Vars(r)["id"]
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
	if err := uuid.Validate(friendID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid ID in JWT", slog.Any("error", err))
		http.Error(w, "Invalid ID in JWT", http.StatusBadRequest)
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
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if rows == 0 {
		env.Logger.ErrorContext(ctx, "No rows affected. Friendship not found.", slog.Any("error", err))
		http.Error(w, "Friendship not found", http.StatusNotFound)
		return
	}

	env.Logger.DebugContext(ctx, "Successfully removed friendship")
	w.WriteHeader(http.StatusOK)
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
	direction := strings.ToLower(r.URL.Query().Get("direction"))

	if direction != "incoming" && direction != "outgoing" && direction != "all" {
		env.Logger.ErrorContext(ctx, "Invalid direction", slog.String("direction", direction))
		http.Error(w, "Invalid direction", http.StatusBadRequest)
		return
	}
	if err := uuid.Validate(userID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid ID in JWT", slog.Any("error", err))
		http.Error(w, "Invalid ID in JWT", http.StatusBadRequest)
		return
	}

	// List friend requests
	var friendRequests []models.FriendRequest
	if direction == "incoming" {
		rows, err := env.Database.ListIncomingRequests(ctx, uuid.MustParse(userID))
		if err != nil {
			env.Logger.ErrorContext(ctx, "Unable to list requests", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		friendRequests, err = copyIncomingRequeststoFriendRequest(rows)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Unable to copy request", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	} else if direction == "outgoing" {
		rows, err := env.Database.ListOutgoingRequests(ctx, uuid.MustParse(userID))
		if err != nil {
			env.Logger.ErrorContext(ctx, "Unable to list requests", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		friendRequests, err = copyOutgoingRequeststoFriendRequest(rows)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Unable to copy request", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	} else {
		rows, err := env.Database.ListRequests(ctx, uuid.MustParse(userID))
		if err != nil {
			env.Logger.ErrorContext(ctx, "Unable to list requests", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		friendRequests, err = copyRequeststoFriendRequest(rows)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Unable to copy request", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}

	// Process response
	env.Logger.DebugContext(ctx, "Processing response")
	response := responses.ListFriendRequests{
		Incoming: make([]models.FriendRequest, 0),
		Outgoing: make([]models.FriendRequest, 0),
	}
	for _, v := range friendRequests {
		if v.User.ID != v.Friendship.RequesterID {
			response.Outgoing = append(response.Outgoing, v)
		} else {
			response.Incoming = append(response.Incoming, v)
		}
	}

	// Encode response
	env.Logger.DebugContext(ctx, "Encoding response")
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to encode friend requests response", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
	defer r.Body.Close()
	err = hathrJson.DecodeJson(&friendRequest, decoder)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to decode request", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Validate request body
	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(friendRequest); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to validate request body", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if err := uuid.Validate(userID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid ID in JWT", slog.Any("error", err))
		http.Error(w, "Invalid ID in JWT", http.StatusBadRequest)
		return
	}

	// Creating friend request in the database
	env.Logger.DebugContext(ctx, "Creating friend request in DB")
	friendship, err := env.Database.CreateFriendRequest(ctx, database.CreateFriendRequestParams{
		Requester: uuid.MustParse(userID),
		Requestee: friendRequest.UserID,
	})

	var pgErr *pgconn.PgError
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

	// TODO: Send notification to the user about the friend request
	env.Logger.DebugContext(ctx, "Encoding response")
	if err := json.NewEncoder(w).Encode(friendship); err != nil {
		env.Logger.ErrorContext(ctx, "Unable to encode response", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func DeleteFriendRequest(w http.ResponseWriter, r *http.Request) {
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
	requesteeID := mux.Vars(r)["id"]

	// Validate request parameters
	if err := uuid.Validate(userID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid ID in JWT in JWT", slog.Any("error", err))
		http.Error(w, "Invalid ID in JWT", http.StatusBadRequest)
		return
	}
	if err := uuid.Validate(requesteeID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid friend ID in route parameter", slog.Any("error", err))
		http.Error(w, "Invalid ID in route parameter", http.StatusBadRequest)
		return
	}

	// Remove friend request in the database
	env.Logger.DebugContext(ctx, "Removing friend request in DB")
	rows, err := env.Database.DeleteFriendRequest(ctx, database.DeleteFriendRequestParams{
		RequesterID: uuid.MustParse(userID),
		RequesteeID: uuid.MustParse(requesteeID),
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
	w.WriteHeader(http.StatusOK)
}

func UpdateFriendshipStatus(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	// Retrieve request parameters
	env.Logger.DebugContext(ctx, "Retrieving request parameters")
	requesterID := mux.Vars(r)["id"]
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

	var friendRequest requests.UpdateFriendshipStatus
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	defer r.Body.Close()
	err = hathrJson.DecodeJson(&friendRequest, decoder)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to decode request", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Validate request body
	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(friendRequest); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to validate request body", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if err := uuid.Validate(userID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid ID in JWT", slog.Any("error", err))
		http.Error(w, "Invalid ID in JWT", http.StatusBadRequest)
		return
	}
	if err := uuid.Validate(requesterID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid friend ID in route parameter", slog.Any("error", err))
		http.Error(w, "Invalid ID in route parameter", http.StatusBadRequest)
		return
	}

	// TODO: add blocking status
	// Respond to friend request in the database
	env.Logger.DebugContext(ctx, "Updating friend request in DB")
	friendship, err := env.Database.AcceptFriendRequest(ctx, database.AcceptFriendRequestParams{
		ResponderID: uuid.MustParse(userID),
		RespondeeID: uuid.MustParse(requesterID),
	})

	if errors.Is(err, pgx.ErrNoRows) {
		env.Logger.ErrorContext(ctx, "Friendship not found. Nothing updated", slog.Any("error", err))
		http.Error(w, "Friend request not found", http.StatusNotFound)
		return
	}
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to respond to friend request", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	env.Logger.DebugContext(ctx, "Encoding response")
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(responses.UpdateFriendshipStatus{
		Friendship: friendship,
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to encode response", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func Search(w http.ResponseWriter, r *http.Request) {
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
		env.Logger.ErrorContext(ctx, "Invalid ID in JWT", slog.Any("error", err))
		http.Error(w, "Invalid ID in JWT", http.StatusBadRequest)
		return
	}
	query := r.URL.Query().Get("q")
	if query == "" {
		env.Logger.ErrorContext(ctx, "Missing query parameter 'q'")
		http.Error(w, "Query parameter 'q' is required", http.StatusBadRequest)
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
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	users := make([]responses.UserWithFriendship, len(dbUsers))
	for i, dbUser := range dbUsers {
		// Unmarshal spotify data
		user, err := buildPublicUser(dbUser.User)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Unable to build user", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		users[i] = responses.UserWithFriendship{
			User:       user,
			Friendship: nil,
		}
		if dbUser.Status.Valid {
			friendship := database.Friendship{
				UserAID:     dbUser.UserAID,
				UserBID:     dbUser.UserBID,
				RequesterID: dbUser.RequesterID,
				Status:      dbUser.Status.FriendshipStatus,
				RequestedAt: dbUser.RequestedAt,
				RespondedAt: dbUser.RespondedAt,
			}
			users[i].Friendship = &friendship
		}
	}

	// Encode response
	env.Logger.DebugContext(ctx, "Encoding response")
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(responses.SearchUsers{
		Users: users,
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to encode search response", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func GetPersonalProfile(w http.ResponseWriter, r *http.Request) {
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
		env.Logger.ErrorContext(ctx, "Invalid ID in JWT", slog.Any("error", err))
		http.Error(w, "Invalid ID in JWT", http.StatusBadRequest)
		return
	}

	// Search for user
	env.Logger.DebugContext(ctx, "Searching for user in DB")
	dbUser, err := env.Database.GetPersonalProfile(ctx, uuid.MustParse(userID))

	// something crazy has happened
	if errors.Is(err, pgx.ErrNoRows) {
		env.Logger.ErrorContext(ctx, "User not found", slog.Any("error", err))
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to retrieve user", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// build user
	user, err := buildUserProfile(dbUser)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to build user profile", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Encode response
	env.Logger.DebugContext(ctx, "Encoding response")
	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(user); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to encode user response", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func GetUserByUsername(w http.ResponseWriter, r *http.Request) {
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
	searcherID, err := jwt.Claims.GetSubject()
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to get user ID from JWT claims")
		http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
		return
	}
	username := mux.Vars(r)["username"]

	// Validate parameters
	env.Logger.DebugContext(ctx, "Validating parameters")
	if err := uuid.Validate(searcherID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid ID in JWT", slog.Any("error", err))
		http.Error(w, "Invalid ID in JWT", http.StatusBadRequest)
		return
	}

	// Search for user
	env.Logger.DebugContext(ctx, "Searching for user in DB")
	dbUser, err := env.Database.GetUserByUsername(ctx, database.GetUserByUsernameParams{
		Searcher: uuid.MustParse(searcherID),
		Username: username,
	})

	if errors.Is(err, pgx.ErrNoRows) {
		env.Logger.ErrorContext(ctx, "User not found", slog.Any("error", err))
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to retrieve user", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Build public user
	env.Logger.DebugContext(ctx, "Building public user")
	user, err := buildPublicUser(dbUser)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to build user", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Encode response
	env.Logger.DebugContext(ctx, "Encoding response")
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(user)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to encode user response", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func GetUserPlaylists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	// Get parameters
	env.Logger.DebugContext(ctx, "Retrieving request parameters")
	jwt, ok := ctx.Value("jwt").(*jwt.Token)
	if !ok {
		env.Logger.ErrorContext(ctx, "Failed to get JWT claims")
		http.Error(w, "JWT not found", http.StatusUnauthorized)
		return
	}
	searcherID, err := jwt.Claims.GetSubject()
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to get user ID from JWT claims")
		http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
		return
	}
	username := mux.Vars(r)["username"]

	// Validate parameters
	env.Logger.DebugContext(ctx, "Validating parameters")
	if err := uuid.Validate(searcherID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid ID in JWT", slog.Any("error", err))
		http.Error(w, "Invalid ID in JWT", http.StatusBadRequest)
		return
	}

	// Retrieve playlists from DB
	env.Logger.DebugContext(ctx, "Retrieving playlists from DB")
	dbPlaylists, err := env.Database.GetUserPlaylists(ctx, database.GetUserPlaylistsParams{
		UserID: uuid.MustParse(searcherID),
		Username: pgtype.Text{
			String: username,
			Valid:  true,
		},
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to get user playlists", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Build response
	response := responses.GetUserPlaylists{
		Playlists: make([]models.PlaylistWithoutTracks, len(dbPlaylists)),
	}
	for i, dbPlaylist := range dbPlaylists {
		response.Playlists[i] = models.PlaylistWithoutTracks{
			Day:        uint8(dbPlaylist.Day),
			Year:       uint16(dbPlaylist.Year),
			NumTracks:  uint16(dbPlaylist.NumTracks),
			Visibility: dbPlaylist.Visibility,
			CreatedAt:  dbPlaylist.CreatedAt.Time,
			ID:         dbPlaylist.ID,
			UserID:     dbPlaylist.UserID,
			Name:       dbPlaylist.Name,
			Type:       string(dbPlaylist.Type),
			ImageURL:   dbPlaylist.ImageUrl,
		}
		month, err := models.GetMonth(int(dbPlaylist.Month))
		if err != nil {
			env.Logger.ErrorContext(ctx, "Invalid month in playlist", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		response.Playlists[i].Month = month
	}

	// Encode response
	env.Logger.DebugContext(ctx, "Encoding response")
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to encode user playlists", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

// TODO: Encorporate blocking
func GetUserFriends(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	// Retrieve request parameters
	env.Logger.DebugContext(ctx, "Retrieving request parameters")
	username := mux.Vars(r)["username"]

	// List friends
	env.Logger.DebugContext(ctx, "Listing friends from DB")
	friends, err := env.Database.ListFriendsByUsername(ctx, pgtype.Text{
		String: username,
		Valid:  true,
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to list friends", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Process friends data
	env.Logger.DebugContext(ctx, "Processing friends data")
	responseFriends := make([]models.PublicUser, len(friends))
	for i, f := range friends {
		user, err := buildPublicUser(f)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Unable to unmarshal spotify user data", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		responseFriends[i] = user
	}

	// Encode response
	env.Logger.DebugContext(ctx, "Encoding response")
	err = json.NewEncoder(w).Encode(responses.ListFriends{
		Friends: responseFriends,
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to encode friends response", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func GetFriendsPlaylists(w http.ResponseWriter, r *http.Request) {
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
		env.Logger.ErrorContext(ctx, "Invalid user ID in JWT", slog.Any("error", err))
		http.Error(w, "Invalid user ID in JWT", http.StatusBadRequest)
		return
	}

	// Get playlists
	env.Logger.DebugContext(ctx, "Retrieving playlists from DB")
	rows, err := env.Database.GetFriendPlaylists(ctx, uuid.MustParse(userID))
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to get friend playlists", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Build response
	env.Logger.DebugContext(ctx, "Building response")
	response := make([]models.UserAndPlaylistWithoutTracks, 0)
	for i, row := range rows {

		// If any of the playlist fields are null, there is no playlist associated with this user, skip
		if row.Playlist.Day == nil {
			continue
		}

		user, err := buildPublicUser(row.User)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Unable to build user", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		response = append(response, models.UserAndPlaylistWithoutTracks{
			User: user,
			Playlist: models.PlaylistWithoutTracks{
				Day:        *row.Playlist.Day,
				Year:       *row.Playlist.Year,
				NumTracks:  *row.Playlist.NumTracks,
				Visibility: *row.Playlist.Visibility,
				CreatedAt:  *row.Playlist.CreatedAt,
				ID:         *row.Playlist.ID,
				UserID:     row.User.ID,
				Name:       *row.Playlist.Name,
				Type:       *row.Playlist.Type,
				ImageURL:   *row.Playlist.ImageURL,
			},
		})

		month, err := models.GetMonth(int(*row.Playlist.Month))
		if err != nil {
			env.Logger.ErrorContext(ctx, "Invalid month in playlist", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		response[i].Playlist.Month = month
	}

	// Encode response
	env.Logger.DebugContext(ctx, "Encoding response")
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(responses.GetFriendPlaylists{Playlists: response})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to encode friend playlists response", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func UpdatePersonalProfile(w http.ResponseWriter, r *http.Request) {
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

	var requestBody requests.UpdateUserProfile
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	defer r.Body.Close()
	if err := hathrJson.DecodeJson(&requestBody, decoder); err != nil {
		env.Logger.ErrorContext(ctx, "Unable to decode request", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Validate parameters
	env.Logger.DebugContext(ctx, "Validating parameters")
	if err := uuid.Validate(userID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid user ID in JWT", slog.Any("error", err))
		http.Error(w, "Invalid user ID in JWT", http.StatusBadRequest)
		return
	}
	if requestBody.DisplayName == nil && requestBody.Username == nil && requestBody.Email == nil {
		env.Logger.ErrorContext(ctx, "No fields to update")
		http.Error(w, "Must specify a field to update", http.StatusBadRequest)
		return
	}
	if requestBody.Username != nil {
		if err := validateUsername(*requestBody.Username); err != nil {
			env.Logger.ErrorContext(ctx, "Invalid username", slog.String("username", *requestBody.Username))
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if requestBody.DisplayName != nil {
		if err := validateDisplayName(*requestBody.DisplayName); err != nil {
			env.Logger.ErrorContext(ctx, "Invalid display name", slog.String("display_name", *requestBody.DisplayName), slog.Any("error", err))
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if requestBody.Email != nil {
		if _, err := mail.ParseAddress(*requestBody.Email); err != nil {
			env.Logger.ErrorContext(ctx, "Invalid email address", slog.String("email", *requestBody.Email))
			http.Error(w, "Invalid email address", http.StatusBadRequest)
			return
		}
	}

	// Update user profile
	env.Logger.DebugContext(ctx, "Updating user profile in DB")
	params := database.UpdateUserProfileParams{}
	params.DisplayName.Valid = requestBody.DisplayName != nil
	if requestBody.DisplayName != nil {
		params.DisplayName.String = *requestBody.DisplayName
	}
	params.Username.Valid = requestBody.Username != nil
	if requestBody.Username != nil {
		params.Username.String = *requestBody.Username
	}
	params.Email.Valid = requestBody.Email != nil
	if requestBody.Email != nil {
		params.Email.String = *requestBody.Email
	}
	params.ID = uuid.MustParse(userID)
	res, err := env.Database.UpdateUserProfile(ctx, params)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		env.Logger.ErrorContext(ctx, "Username already taken", slog.Any("error", err))
		http.Error(w, "Username unavailable", http.StatusConflict)
		return
	} else if errors.Is(err, pgx.ErrNoRows) {
		env.Logger.ErrorContext(ctx, "User not found")
		http.Error(w, "User not found", http.StatusNotFound)
		return
	} else if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to update user profile", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Build response
	env.Logger.DebugContext(ctx, "Building response")
	user, err := buildUserProfile(res)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Unable to build user", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Encode response
	env.Logger.DebugContext(ctx, "Encoding response")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(user); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to encode user response", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func UpdateSpotifyPlays(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	// Retrieve request parameters
	env.Logger.DebugContext(ctx, "Retrieving request parameters")
	userID := mux.Vars(r)["id"]

	var request requests.UpdateSpotifyPlays
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	defer r.Body.Close()
	if err := hathrJson.DecodeJson(&request, decoder); err != nil {
		env.Logger.ErrorContext(ctx, "Unable to decode request", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Validate parameters
	env.Logger.DebugContext(ctx, "Validating parameters")
	if err := uuid.Validate(userID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid user ID in route parameter", slog.Any("error", err))
		http.Error(w, "Invalid user ID in route parameter", http.StatusBadRequest)
		return
	}
	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(request); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to validate request body", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Retrieve spotify tokens
	accessToken, err := retrieveSpotifyToken(uuid.MustParse(userID), env, ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		env.Logger.ErrorContext(ctx, "Spotify tokens not found for user", slog.Any("error", err))
		http.Error(w, "Spotify tokens not found for user", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Retrieve recent plays
	env.Logger.DebugContext(ctx, "Retrieving recent plays from Spotify")
	recentTracks, err := hathrSpotify.GetRecentlyPlayedTracks(accessToken, request.After, env, ctx)
	var spotifyErr *hathrHttp.HTTPError
	if errors.As(err, &spotifyErr) && spotifyErr.StatusCode == http.StatusUnauthorized {
		env.Logger.ErrorContext(ctx, "Spotify rate limit exceeded", slog.Any("error", err))
		http.Error(w, "Spotify rate limit exceeded", http.StatusTooManyRequests)
		return
	} else if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to retrieve recent plays from Spotify", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Create tracks
	tracks := make([]spotifyModels.SpotifyTrackInput, len(recentTracks.Items))
	ids := make([]string, len(recentTracks.Items))
	played := make([]pgtype.Timestamptz, len(recentTracks.Items))

	env.Logger.DebugContext(ctx, "Processing tracks")
	for i, playHistory := range recentTracks.Items {
		ids[i] = playHistory.Track.ID
		played[i] = pgtype.Timestamptz{
			Time:  playHistory.PlayedAt,
			Valid: true,
		}
		artists := make([]string, len(playHistory.Track.Artists))
		for j, artist := range playHistory.Track.Artists {
			artists[j] = artist.Name
		}
		raw, err := json.Marshal(playHistory.Track)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Failed to marshal track data", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		tracks[i] = spotifyModels.SpotifyTrackInput{
			ID:      playHistory.Track.ID,
			Name:    playHistory.Track.Name,
			Artists: artists,
			ImageURL: pgtype.Text{
				String: extractLargestImage(playHistory.Track.Album.Images),
				Valid:  true,
			},
			Popularity: int(playHistory.Track.Popularity),
			Raw:        raw,
			Href:       playHistory.Track.ExternalURLs.Spotify,
		}
	}

	// Insert tracks into the database
	env.Logger.DebugContext(ctx, "Inserting tracks into DB")
	err = env.Database.CreateSpotifyTracks(ctx, tracks)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to insert tracks into DB", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Insert plays into the database
	env.Logger.DebugContext(ctx, "Inserting plays into DB")
	err = env.Database.CreateSpotifyPlays(ctx, database.CreateSpotifyPlaysParams{
		UserID: uuid.MustParse(userID),
		Ids:    ids,
		Played: played,
	})
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	env.Logger.DebugContext(ctx, "Successfully updated Spotify plays")
}

func ListRegisteredUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	// Retrieve request parameters
	env.Logger.DebugContext(ctx, "Retrieving request parameters")
	limitQuery := r.URL.Query().Get("limit")
	if limitQuery == "" {
		limitQuery = "10" // Default limit if not provided
	}

	afterQuery := r.URL.Query().Get("after")
	if afterQuery == "" {
		afterQuery = uuid.Nil.String() // Default to nil UUID if not provided
	}

	// Validate request parameters
	env.Logger.DebugContext(ctx, "Validating request parameters")
	intLimit, err := strconv.Atoi(limitQuery)
	if err != nil || intLimit <= 0 || intLimit > 100 {
		env.Logger.ErrorContext(ctx, "Invalid limit", slog.Any("error", err))
		http.Error(w, "Invalid limit", http.StatusBadRequest)
		return
	}

	if err := uuid.Validate(afterQuery); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid after ID", slog.Any("error", err))
		http.Error(w, "Invalid after ID", http.StatusBadRequest)
		return
	}

	// Fetch registered users from the database
	env.Logger.DebugContext(ctx, "Fetching registered users from DB")
	ids, err := env.Database.ListRegisteredUsers(ctx, database.ListRegisteredUsersParams{
		After: uuid.MustParse(afterQuery),
		Lim:   int32(intLimit),
	})
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to list registered users", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Build response
	env.Logger.DebugContext(ctx, "Building response")
	response := responses.ListRegisteredUsers{
		IDs: ids,
	}
	if ids == nil {
		response.IDs = make([]uuid.UUID, 0)
	}
	if len(ids) != 0 {
		response.Next = ids[len(ids)-1]
	}

	w.Header().Add("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to encode response", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func ReleasePlaylists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	// Retrieve request parameters
	env.Logger.DebugContext(ctx, "Retrieving request parameters")
	var body requests.ReleasePlaylists
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	defer r.Body.Close()
	if err := hathrJson.DecodeJson(&body, decoder); err != nil {
		env.Logger.ErrorContext(ctx, "Unable to decode request", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Validate user ID
	validate := validator.New()
	if err := validate.Struct(body); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to validate request body", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if body.Type == "weekly" && body.Day < 1 || body.Day > 31 {
		env.Logger.ErrorContext(ctx, "Invalid day", slog.Int("day", int(body.Day)))
		http.Error(w, "Invalid day", http.StatusBadRequest)
		return
	}
	if body.Year < 2025 || body.Year > 9999 {
		env.Logger.ErrorContext(ctx, "Invalid year", slog.Uint64("year", uint64(body.Year)))
		http.Error(w, "Invalid year", http.StatusBadRequest)
		return
	}

	// Release playlists in the database
	var err error
	var rows int64
	if body.Type == "monthly" {
		env.Logger.DebugContext(ctx, "Releasing monthly playlists in DB", slog.Uint64("year", uint64(body.Year)), slog.String("month", string(body.Month)))
		rows, err = env.Database.ReleaseMonthlyPlaylists(ctx, database.ReleaseMonthlyPlaylistsParams{
			Year:  int32(body.Year),
			Month: int32(body.Month.Index() + 1),
		})
	} else if body.Type == "weekly" {
		env.Logger.DebugContext(ctx, "Releasing weekly playlists in DB", slog.Int("year", int(body.Year)), slog.String("month", string(body.Month)), slog.Int("day", int(body.Day)))
		rows, err = env.Database.ReleaseWeeklyPlaylists(ctx, database.ReleaseWeeklyPlaylistsParams{
			Year:  int32(body.Year),
			Month: int32(body.Month.Index() + 1),
			Day:   int32(body.Day),
		})
	}
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to release playlists in DB", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	} else if rows == 0 {
		env.Logger.ErrorContext(ctx, "No playlists released", slog.Int64("rows", rows))
		http.Error(w, "No playlists released", http.StatusNotFound)
		return
	}

	env.Logger.DebugContext(ctx, "Successfully released playlists")
}

func CreatePlaylistCover(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	// Retrieve request parameters
	env.Logger.DebugContext(ctx, "Retrieving request parameters")
	var body requests.CreatePlaylistImage
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	defer r.Body.Close()
	if err := hathrJson.DecodeJson(&body, decoder); err != nil {
		env.Logger.ErrorContext(ctx, "Unable to decode request", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Validate user ID
	env.Logger.DebugContext(ctx, "Validating request body")
	validate := validator.New()
	if err := validate.Struct(body); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to validate request body", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	var response covers.CreateImageCoverResponse
	var err error
	var httpError *hathrHttp.HTTPError
	env.Logger.DebugContext(ctx, "Creating playlist image cover", slog.Int("year", int(body.Year)), slog.String("month", string(body.Month)), slog.Int("day", int(body.Day)), slog.String("type", string(body.Type)))
	if body.Type == "weekly" {
		response, err = covers.CreateMonthlyImageCover(covers.CreateMonthlyImageCoverParams{
			Month: models.Month(body.Month),
			Year:  uint16(body.Year),
		}, env)
	} else if body.Type == "monthly" {
		date1, err := loadDate(int(body.Year), time.Month(body.Month.Index()+1), int(body.Day), 0, 0, 0, 0)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Failed to load date", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		date2 := date1.AddDate(0, 0, 7)
		response, err = covers.CreateWeeklyImageCover(covers.CreateWeeklyImageCoverParams{
			Day1:   uint8(date1.Day()),
			Day2:   uint8(date2.Day()),
			Year1:  uint16(date1.Year()),
			Year2:  uint16(date2.Year()),
			Month1: models.Month(date1.Month().String()),
			Month2: models.Month(date2.Month().String()),
		}, env)
	}

	if errors.As(err, &httpError) {
		env.Logger.ErrorContext(ctx, "Failed to create playlist image", slog.Any("error", err))
		if httpError.StatusCode == http.StatusUnprocessableEntity {
			http.Error(w, http.StatusText(httpError.StatusCode), httpError.StatusCode)
		} else {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	} else if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to create playlist image", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Encode response
	env.Logger.DebugContext(ctx, "Successfully created playlist image")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to encode response", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func AddPlaylistToSpotify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	env, ok := r.Context().Value(hathrEnv.Key).(*hathrEnv.Env)
	if !ok {
		env = hathrEnv.Null()
	}

	// Retrieve request parameters
	playlistID := mux.Vars(r)["playlist_id"]
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

	// Validate user ID
	env.Logger.DebugContext(ctx, "Validating request body")
	if err := uuid.Validate(playlistID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid playlist ID in route parameter", slog.Any("error", err))
		http.Error(w, "Invalid playlist ID in route parameter", http.StatusBadRequest)
	}
	if err := uuid.Validate(userID); err != nil {
		env.Logger.ErrorContext(ctx, "Invalid user ID in JWT", slog.Any("error", err))
		http.Error(w, "Invalid user ID in JWT", http.StatusBadRequest)
		return
	}

	// Retrieve playlist from DB
	env.Logger.DebugContext(ctx, "Retrieving playlist from DB")
	playlist, err := env.Database.GetSpotifyPlaylistWithOwner(ctx, uuid.MustParse(playlistID))
	if errors.Is(err, pgx.ErrNoRows) {
		env.Logger.ErrorContext(ctx, "Playlist not found", slog.Any("error", err))
		http.Error(w, "Playlist not found", http.StatusNotFound)
		return
	} else if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to retrieve playlist", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Validate permissions
	if userID != playlist.User.ID.String() && playlist.Playlist.Visibility != database.PlaylistVisibilityPublic || playlist.Playlist.Visibility == database.PlaylistVisibilityUnreleased {
		env.Logger.ErrorContext(ctx, "Unauthorized to add playlist to Spotify", slog.String("user_id", userID), slog.String("playlist_user_id", playlist.User.ID.String()), slog.String("visibility", string(playlist.Playlist.Visibility)))
		http.Error(w, "Unauthorized to add playlist to Spotify", http.StatusForbidden)
		return
	}

	// Retrieve spotify tracks
	env.Logger.DebugContext(ctx, "Retrieving playlist tracks from DB")
	ids, err := env.Database.GetSpotifyPlaylistTrackIDs(ctx, uuid.MustParse(playlistID))
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to retrieve playlist tracks", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Retrieve spotify tokens
	token, err := retrieveSpotifyToken(uuid.MustParse(userID), env, ctx)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Retrieve user spotify id
	spotifyUserID, err := env.Database.GetSpotifyUserID(ctx, uuid.MustParse(userID))
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to retrieve spotify user ID", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if !spotifyUserID.Valid {
		env.Logger.ErrorContext(ctx, "No spotify account associated with user")
		http.Error(w, "No spotify account associated with user", http.StatusNotFound)
		return
	}

	// Create spotify playlist
	env.Logger.DebugContext(ctx, "Creating Spotify playlist")
	spotifyPlaylist, err := hathrSpotify.CreateSpotifyPlaylist(token, spotifyUserID.String, playlist.Playlist.Name, "Autogenerated playlist by Hathr™", env, ctx)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to create Spotify playlist", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	env.Logger.DebugContext(ctx, "Successfully created Spotify playlist", slog.String("spotify_playlist_id", spotifyPlaylist.ID))

	// Add tracks to spotify playlist
	env.Logger.DebugContext(ctx, "Adding tracks to Spotify playlist", slog.Int("num_tracks", len(ids)))
	err = hathrSpotify.AddTracksToPlaylist(token, spotifyPlaylist.ID, ids, env, ctx)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to add tracks to Spotify playlist", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	env.Logger.DebugContext(ctx, "Successfully Added tracks to Spotify playlist")

	// TODO: Add image to spotify playlist

	// Build response
	env.Logger.DebugContext(ctx, "Building response")
	response := responses.AddPlaylistToSpotify{
		URL: spotifyPlaylist.ExternalURLs.Spotify,
	}
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		env.Logger.ErrorContext(ctx, "Failed to encode response", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}
