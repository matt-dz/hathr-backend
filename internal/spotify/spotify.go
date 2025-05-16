// Package for spotify utility functions

package spotify

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	hathrEnv "hathr-backend/internal/env"
	hathrJson "hathr-backend/internal/json"
	spotifyErrors "hathr-backend/internal/spotify/errors"
	spotifyModels "hathr-backend/internal/spotify/models"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/zmb3/spotify/v2"
)

const spotifyBaseURL = "https://api.spotify.com/v1/"
const spotifyAuthURL = "https://accounts.spotify.com/"

func LoginUser(login spotifyModels.LoginRequest, env *hathrEnv.Env, ctx context.Context) (spotifyModels.LoginResponse, spotifyErrors.LoginError, error) {

	// Retrieve environment variables
	redirectURI := os.Getenv("SPOTIFY_REDIRECT_URI")
	if redirectURI == "" {
		env.Logger.ErrorContext(ctx, "SPOTIFY_REDIRECT_URI not set")
		return spotifyModels.LoginResponse{}, spotifyErrors.LoginError{}, fmt.Errorf("SPOTIFY_REDIRECT_URI not set")
	}

	clientID := os.Getenv("SPOTIFY_CLIENT_ID")
	if clientID == "" {
		env.Logger.ErrorContext(ctx, "SPOTIFY_CLIENT_ID not set")
		return spotifyModels.LoginResponse{}, spotifyErrors.LoginError{}, fmt.Errorf("SPOTIFY_CLIENT_ID not set")
	}

	// Create request
	env.Logger.DebugContext(ctx, "Create spotify access token request")
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", login.Code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", clientID)
	data.Set("code_verifier", login.CodeVerifier)
	req, err := retryablehttp.NewRequest(http.MethodPost, spotifyAuthURL+"api/token", strings.NewReader(data.Encode()))
	if err != nil {
		env.Logger.ErrorContext(ctx, "Error creating request", slog.Any("error", err))
		return spotifyModels.LoginResponse{}, spotifyErrors.LoginError{}, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Send request
	env.Logger.DebugContext(ctx, "Sending request", slog.Any("req", req.RequestURI))
	client := retryablehttp.NewClient()
	client.RetryWaitMax = time.Second * 10
	client.Logger = env.Logger
	res, err := client.Do(req)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to send request", slog.Any("error", err))
		return spotifyModels.LoginResponse{}, spotifyErrors.LoginError{}, err
	}

	// If unsuccessful, return error
	if res.StatusCode != http.StatusOK {
		env.Logger.ErrorContext(ctx, "Unsuccessful request", slog.Any("res", res))
		return spotifyModels.LoginResponse{}, spotifyErrors.LoginError{StatusCode: res.StatusCode, Status: res.Status}, nil
	}

	// Decode response
	env.Logger.DebugContext(ctx, "Decoding spotify validation response")
	var loginResponse spotifyModels.LoginResponse
	decoder := json.NewDecoder(res.Body)
	decoder.DisallowUnknownFields()
	defer res.Body.Close()
	err = hathrJson.DecodeJson(&loginResponse, decoder)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Error decoding response", slog.Any("error", err))
		return spotifyModels.LoginResponse{}, spotifyErrors.LoginError{}, err
	}

	return loginResponse, spotifyErrors.LoginError{}, nil
}

// Get a user's profile via their access token
func GetUserProfile(bearerToken string, env *hathrEnv.Env, ctx context.Context) (spotifyModels.User, spotify.Error, error) {

	// Create request
	env.Logger.DebugContext(ctx, "Creating request")
	req, err := retryablehttp.NewRequest(http.MethodGet, spotifyBaseURL+"me", nil)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Error creating request", slog.Any("error", err))
		return spotifyModels.User{}, spotify.Error{}, err
	}
	req.Header.Set("Authorization", bearerToken)

	// Send request
	env.Logger.DebugContext(ctx, "Sending request")
	client := retryablehttp.NewClient()
	client.RetryWaitMax = time.Second * 10
	client.Logger = env.Logger
	res, err := client.Do(req)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to send request", slog.Any("error", err))
		return spotifyModels.User{}, spotify.Error{}, err
	}

	// If official error, decode
	// https://developer.spotify.com/documentation/web-api/reference/get-current-users-profile
	if slices.Contains([]int{401, 403, 429}, res.StatusCode) {
		env.Logger.ErrorContext(ctx, "Unsuccessful request", slog.Any("res", res))
		var spotifyErr spotify.Error
		decoder := json.NewDecoder(res.Body)
		decoder.DisallowUnknownFields()
		defer res.Body.Close()
		err = hathrJson.DecodeJson(&spotifyErr, decoder)
		return spotifyModels.User{}, spotifyErr, err
	} else if res.StatusCode != http.StatusOK {
		// probably a bad request on our part
		env.Logger.ErrorContext(ctx, "Unsuccessful request", slog.Any("res", res))
		return spotifyModels.User{}, spotify.Error{}, fmt.Errorf("Unsuccessful request: %s", res.Status)
	}

	// Decode response
	env.Logger.DebugContext(ctx, "Decoding spotify validation response")
	var user spotifyModels.User
	decoder := json.NewDecoder(res.Body)
	defer res.Body.Close()
	err = hathrJson.DecodeJson(&user, decoder)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Error decoding response", slog.Any("error", err))
		return spotifyModels.User{}, spotify.Error{}, err
	}

	return user, spotify.Error{}, nil
}
