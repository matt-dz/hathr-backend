// Package for spotify utility functions

package spotify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"hathr-backend/internal/env"
	hathrHttp "hathr-backend/internal/http"
	hathrJson "hathr-backend/internal/json"
	"hathr-backend/internal/spotify/models"
	spotifyModels "hathr-backend/internal/spotify/models"

	"github.com/hashicorp/go-retryablehttp"
)

const spotifyBaseURL = "https://api.spotify.com/v1"
const spotifyAuthURL = "https://accounts.spotify.com/"

func LoginUser(login spotifyModels.LoginRequest, env *env.Env, ctx context.Context) (spotifyModels.LoginResponse, error) {

	var loginResponse spotifyModels.LoginResponse

	// Retrieve environment variables
	redirectURI := os.Getenv("SPOTIFY_REDIRECT_URI")
	if redirectURI == "" {
		return loginResponse, fmt.Errorf("SPOTIFY_REDIRECT_URI not set")
	}

	clientID := os.Getenv("SPOTIFY_CLIENT_ID")
	if clientID == "" {
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
		return loginResponse, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Send request
	env.Logger.DebugContext(ctx, "Sending request", slog.Any("req", req.RequestURI))
	res, err := env.Http.Do(req)
	if err != nil {
		return loginResponse, err
	}

	// If unsuccessful, return error
	defer res.Body.Close()
	if res.StatusCode > 299 {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Failed to read body", slog.Any("error", err))
			return loginResponse, hathrHttp.NewHTTPError(res.StatusCode, res.Status, "")
		}
		return loginResponse, hathrHttp.NewHTTPError(res.StatusCode, res.Status, string(body))
	}

	// Decode response
	env.Logger.DebugContext(ctx, "Decoding spotify validation response")
	decoder := json.NewDecoder(res.Body)
	decoder.DisallowUnknownFields()
	err = hathrJson.DecodeJson(&loginResponse, decoder)
	if err != nil {
		return loginResponse, err
	}

	return loginResponse, nil
}

// Get a user's profile via their access token
func GetUserProfile(bearerToken string, env *env.Env, ctx context.Context) (spotifyModels.User, error) {

	var user spotifyModels.User

	// Create request
	env.Logger.DebugContext(ctx, "Creating request")
	req, err := retryablehttp.NewRequest(http.MethodGet, fmt.Sprintf("%s/me", spotifyBaseURL), nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("Authorization", bearerToken)

	// Send request
	env.Logger.DebugContext(ctx, "Sending request")
	res, err := env.Http.Do(req)
	if err != nil {
		return user, err
	}

	// If official error, decode
	// https://developer.spotify.com/documentation/web-api/reference/get-current-users-profile
	defer res.Body.Close()
	if res.StatusCode > 299 {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Failed to read body", slog.Any("error", err))
			return user, hathrHttp.NewHTTPError(res.StatusCode, res.Status, "")
		}
		return user, hathrHttp.NewHTTPError(res.StatusCode, res.Status, string(body))
	}

	// Decode response
	env.Logger.DebugContext(ctx, "Decoding spotify validation response")
	decoder := json.NewDecoder(res.Body)
	err = hathrJson.DecodeJson(&user, decoder)
	if err != nil {
		return user, err
	}

	return user, nil
}

func RefreshToken(refreshToken string, env *env.Env, ctx context.Context) (models.RefreshTokenResponse, error) {

	// Retrieve environment variables
	var refreshTokenResponse models.RefreshTokenResponse
	clientID := os.Getenv("SPOTIFY_CLIENT_ID")
	if clientID == "" {
		return refreshTokenResponse, fmt.Errorf("SPOTIFY_CLIENT_ID not set")
	}
	clientSecret := os.Getenv("SPOTIFY_CLIENT_SECRET")
	if clientSecret == "" {
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
		return refreshTokenResponse, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send request
	env.Logger.DebugContext(ctx, "Sending request", slog.Any("req", req.RequestURI))
	res, err := env.Http.Do(req)
	defer res.Body.Close()
	if err != nil {
		return refreshTokenResponse, err
	}

	// If unsuccessful, return error
	if res.StatusCode > 299 {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Failed to read body", slog.Any("error", err))
			return refreshTokenResponse, hathrHttp.NewHTTPError(res.StatusCode, res.Status, "")
		}
		return refreshTokenResponse, hathrHttp.NewHTTPError(res.StatusCode, res.Status, string(body))
	}
	env.Logger.DebugContext(ctx, "Request successful", slog.Any("status", res.Status))

	// Decode response
	env.Logger.DebugContext(ctx, "Decoding request")
	decoder := json.NewDecoder(res.Body)
	decoder.DisallowUnknownFields()
	if err := hathrJson.DecodeJson(&refreshTokenResponse, decoder); err != nil {
		return refreshTokenResponse, err
	}

	return refreshTokenResponse, nil
}

func GetRecentlyPlayedTracks(accessToken string, after time.Time, env *env.Env, ctx context.Context) (spotifyModels.RecentlyPlayedTracksResponse, error) {

	var response spotifyModels.RecentlyPlayedTracksResponse

	// Create request
	env.Logger.DebugContext(ctx, "Creating request")
	url := fmt.Sprintf("%s/me/player/recently-played?limit=50&after=%d", spotifyBaseURL, after.Unix())
	req, err := retryablehttp.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return response, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	// Send request
	env.Logger.DebugContext(ctx, "Sending request")
	res, err := env.Http.Do(req)
	defer res.Body.Close()
	if err != nil {
		return response, err
	}

	// If unsuccessful, return error
	if res.StatusCode > 299 {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return response, hathrHttp.NewHTTPError(res.StatusCode, res.Status, "")
		}
		return response, hathrHttp.NewHTTPError(res.StatusCode, res.Status, string(body))
	}

	// Decode response
	env.Logger.DebugContext(ctx, "Decoding spotify response")
	if err := hathrJson.DecodeJson(&response, json.NewDecoder(res.Body)); err != nil {
		return response, err
	}

	return response, nil
}

func CreateSpotifyPlaylist(accessToken, userID, name, description string, env *env.Env, ctx context.Context) (spotifyModels.CreatePlaylistResponse, error) {

	var response spotifyModels.CreatePlaylistResponse
	// Build request
	body := models.CreatePlaylistRequest{
		Name:          name,
		Public:        true,
		Collaborative: false,
		Description:   description,
	}
	rawBody, err := json.Marshal(body)
	if err != nil {
		return response, err
	}
	req, err := retryablehttp.NewRequest(http.MethodPost, fmt.Sprintf("%s/users/%s/playlists", spotifyBaseURL, userID), bytes.NewReader(rawBody))
	if err != nil {
		return response, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	// Send request
	res, err := env.Http.Do(req)
	if err != nil {
		return response, err
	}
	defer res.Body.Close()

	if res.StatusCode > 299 {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			env.Logger.Error("Failed to read response body", slog.Any("error", err))
			return response, errors.Join(err, hathrHttp.NewHTTPError(res.StatusCode, res.Status, ""))
		}
		return response, hathrHttp.NewHTTPError(res.StatusCode, res.Status, string(body))
	}

	// Decode response
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return response, err
	}

	return response, nil
}

func AddTracksToPlaylist(accessToken, playlistID string, trackIDs []string, env *env.Env, ctx context.Context) error {
	// Build request
	trackURIs := make([]string, len(trackIDs))
	for i, id := range trackIDs {
		trackURIs[i] = fmt.Sprintf("spotify:track:%s", id)
	}
	body := models.AddTracksRequest{
		URIs: trackURIs,
	}
	rawBody, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := retryablehttp.NewRequest(http.MethodPost, fmt.Sprintf("%s/playlists/%s/tracks", spotifyBaseURL, playlistID), bytes.NewReader(rawBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	// Send request
	res, err := env.Http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode > 299 {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			env.Logger.Error("Failed to read response body", slog.Any("error", err))
			return errors.Join(err, hathrHttp.NewHTTPError(res.StatusCode, res.Status, ""))
		}
		return hathrHttp.NewHTTPError(res.StatusCode, res.Status, string(body))
	}

	return nil
}
