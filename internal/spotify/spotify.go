// Package for spotify utility functions

package spotify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	"hathr-backend/internal/spotify/models"
	spotifyModels "hathr-backend/internal/spotify/models"

	"github.com/hashicorp/go-retryablehttp"
)

const spotifyBaseURL = "https://api.spotify.com/v1"
const spotifyAuthURL = "https://accounts.spotify.com/"

func LoginUser(login spotifyModels.LoginRequest, env *hathrEnv.Env, ctx context.Context) (spotifyModels.LoginResponse, error) {

	var loginResponse spotifyModels.LoginResponse

	// Retrieve environment variables
	redirectURI := os.Getenv("SPOTIFY_REDIRECT_URI")
	if redirectURI == "" {
		env.Logger.ErrorContext(ctx, "SPOTIFY_REDIRECT_URI not set")
		return loginResponse, fmt.Errorf("SPOTIFY_REDIRECT_URI not set")
	}

	clientID := os.Getenv("SPOTIFY_CLIENT_ID")
	if clientID == "" {
		env.Logger.ErrorContext(ctx, "SPOTIFY_CLIENT_ID not set")
		return loginResponse, fmt.Errorf("SPOTIFY_CLIENT_ID not set")
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
		return loginResponse, err
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
		return loginResponse, err
	}

	// If unsuccessful, return error
	if res.StatusCode != http.StatusOK {
		env.Logger.ErrorContext(ctx, "Unsuccessful request", slog.Any("res", res))
		body, err := io.ReadAll(res.Body)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Failed to read body", slog.Any("error", err))
		}
		env.Logger.ErrorContext(ctx, "decoded body", slog.String("status", res.Status), slog.String("body", string(body)))
		return loginResponse, &spotifyErrors.SpotifyError{StatusCode: res.StatusCode, Status: res.Status, Message: string(body)}
	}

	// Decode response
	env.Logger.DebugContext(ctx, "Decoding spotify validation response")
	decoder := json.NewDecoder(res.Body)
	decoder.DisallowUnknownFields()
	defer res.Body.Close()
	err = hathrJson.DecodeJson(&loginResponse, decoder)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Error decoding response", slog.Any("error", err))
		return loginResponse, err
	}

	return loginResponse, nil
}

// Get a user's profile via their access token
func GetUserProfile(bearerToken string, env *hathrEnv.Env, ctx context.Context) (spotifyModels.User, error) {

	var user spotifyModels.User

	// Create request
	env.Logger.DebugContext(ctx, "Creating request")
	req, err := retryablehttp.NewRequest(http.MethodGet, fmt.Sprintf("%s/me", spotifyBaseURL), nil)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Error creating request", slog.Any("error", err))
		return user, err
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
		return user, err
	}

	// If official error, decode
	// https://developer.spotify.com/documentation/web-api/reference/get-current-users-profile
	if slices.Contains([]int{401, 403, 429}, res.StatusCode) {
		env.Logger.ErrorContext(ctx, "Unsuccessful request", slog.Any("res", res))
		body, err := io.ReadAll(res.Body)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Failed to read body", slog.Any("error", err))
		}
		env.Logger.ErrorContext(ctx, "decoded body", slog.String("status", res.Status), slog.String("body", string(body)))
		return user, &spotifyErrors.SpotifyError{
			StatusCode: res.StatusCode,
			Status:     res.Status,
			Message:    string(body),
		}
	} else if res.StatusCode != http.StatusOK {
		// probably a bad request on our part
		env.Logger.ErrorContext(ctx, "Unsuccessful request", slog.Any("res", res))
		return user, fmt.Errorf("Unsuccessful request: %s", res.Status)
	}

	// Decode response
	env.Logger.DebugContext(ctx, "Decoding spotify validation response")
	decoder := json.NewDecoder(res.Body)
	defer res.Body.Close()
	err = hathrJson.DecodeJson(&user, decoder)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Error decoding response", slog.Any("error", err))
		return user, err
	}

	return user, nil
}

func RefreshToken(refreshToken string, env *hathrEnv.Env, ctx context.Context) (models.RefreshTokenResponse, error) {

	// Retrieve environment variables
	var refreshTokenResponse models.RefreshTokenResponse
	clientID := os.Getenv("SPOTIFY_CLIENT_ID")
	if clientID == "" {
		env.Logger.ErrorContext(ctx, "SPOTIFY_CLIENT_ID not set")
		return refreshTokenResponse, fmt.Errorf("SPOTIFY_CLIENT_ID not set")
	}
	clientSecret := os.Getenv("SPOTIFY_CLIENT_SECRET")
	if clientSecret == "" {
		env.Logger.ErrorContext(ctx, "SPOTIFY_CLIENT_SECRET not set")
		return refreshTokenResponse, fmt.Errorf("SPOTIFY_CLIENT_SECRET not set")
	}

	// Create request
	env.Logger.DebugContext(ctx, "Create spotify refresh token request")
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", clientID)
	req, err := retryablehttp.NewRequest(http.MethodPost, spotifyAuthURL+"api/token", strings.NewReader(data.Encode()))
	if err != nil {
		env.Logger.ErrorContext(ctx, "Error creating request", slog.Any("error", err))
		return refreshTokenResponse, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send request
	env.Logger.DebugContext(ctx, "Sending request", slog.Any("req", req.RequestURI))
	client := retryablehttp.NewClient()
	client.RetryWaitMax = time.Second * 10
	client.Logger = env.Logger
	res, err := client.Do(req)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to send request", slog.Any("error", err))
		return refreshTokenResponse, err
	}

	// If unsuccessful, return error
	if res.StatusCode != http.StatusOK {
		env.Logger.ErrorContext(ctx, "Unsuccessful request", slog.Any("res", res))
		body, err := io.ReadAll(res.Body)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Failed to read body", slog.Any("error", err))
		}
		env.Logger.ErrorContext(ctx, "decoded body", slog.String("status", res.Status), slog.String("body", string(body)))
		return refreshTokenResponse, &spotifyErrors.SpotifyError{StatusCode: res.StatusCode, Status: res.Status, Message: string(body)}
	}
	env.Logger.DebugContext(ctx, "Request successful", slog.Any("status", res.Status))

	// Decode response
	env.Logger.DebugContext(ctx, "Decoding request")
	decoder := json.NewDecoder(res.Body)
	decoder.DisallowUnknownFields()
	if err := hathrJson.DecodeJson(&refreshTokenResponse, decoder); err != nil {
		env.Logger.ErrorContext(ctx, "Error decoding response", slog.Any("error", err))
		return refreshTokenResponse, err
	}

	return refreshTokenResponse, nil
}

func GetRecentlyPlayedTracks(accessToken string, after time.Time, env *hathrEnv.Env, ctx context.Context) (spotifyModels.RecentlyPlayedTracksResponse, error) {

	var response spotifyModels.RecentlyPlayedTracksResponse

	// Create request
	env.Logger.DebugContext(ctx, "Creating request")
	url := fmt.Sprintf("%s/me/player/recently-played?limit=50&after=%d", spotifyBaseURL, after.Unix())
	req, err := retryablehttp.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Error creating request", slog.Any("error", err))
		return response, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	// Send request
	env.Logger.DebugContext(ctx, "Sending request")
	client := retryablehttp.NewClient()
	client.RetryWaitMax = time.Second * 10
	client.Logger = env.Logger
	res, err := client.Do(req)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Failed to send request", slog.Any("error", err))
		return response, err
	}

	// If unsuccessful, return error
	if res.StatusCode != http.StatusOK {
		env.Logger.ErrorContext(ctx, "Unsuccessful request", slog.Any("res", res))
		body, err := io.ReadAll(res.Body)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Failed to read body", slog.Any("error", err))
		}
		env.Logger.ErrorContext(ctx, "decoded body", slog.String("status", res.Status), slog.String("body", string(body)))
		return response, &spotifyErrors.SpotifyError{StatusCode: res.StatusCode, Status: res.Status, Message: string(body)}
	}

	// Decode response
	env.Logger.DebugContext(ctx, "Decoding spotify response")
	defer res.Body.Close()
	if err := hathrJson.DecodeJson(&response, json.NewDecoder(res.Body)); err != nil {
		env.Logger.ErrorContext(ctx, "Error decoding response", slog.Any("error", err))
		return response, err
	}

	env.Logger.InfoContext(ctx, "Successfully retrieved recently played tracks", slog.Int("count", len(response.Items)))
	return response, nil
}
