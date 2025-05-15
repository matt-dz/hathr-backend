// Package for spotify utility functions

package spotify

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
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
	// Create request
	env.Logger.DebugContext(ctx, "Create spotify access token request")
	data := url.Values{}
	data.Set("grant_type", login.GrantType)
	data.Set("code", login.Code)
	data.Set("redirect_uri", login.RedirectURI)
	data.Set("client_id", login.ClientID)
	data.Set("code_verifier", login.CodeVerifier)
	req, err := retryablehttp.NewRequest(http.MethodPost, spotifyAuthURL+"api/token", strings.NewReader(data.Encode()))
	if err != nil {
		env.Logger.ErrorContext(ctx, "Error creating request", slog.Any("error", err))
		return spotifyModels.LoginResponse{}, spotifyErrors.LoginError{}, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Send request
	env.Logger.DebugContext(ctx, "Sending request")
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
		env.Logger.ErrorContext(ctx, "Unsuccessful request", slog.Any("error", err))
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
func GetUserProfile(bearerToken string, env *hathrEnv.Env, ctx context.Context) (spotify.PrivateUser, spotify.Error, error) {

	// Create request
	env.Logger.DebugContext(ctx, "Creating spotify validation request")
	req, err := retryablehttp.NewRequest(http.MethodGet, spotifyBaseURL+"me", nil)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Error creating request", slog.Any("error", err))
		return spotify.PrivateUser{}, spotify.Error{}, err
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
		return spotify.PrivateUser{}, spotify.Error{}, err
	}

	// If unsuccessful, decode error
	if res.StatusCode != http.StatusOK {
		env.Logger.ErrorContext(ctx, "Unsuccessful request", slog.Any("error", err))
		var spotifyErr spotify.Error
		decoder := json.NewDecoder(res.Body)
		decoder.DisallowUnknownFields()
		defer res.Body.Close()
		err = hathrJson.DecodeJson(&spotifyErr, decoder)
		if err != nil {
			return spotify.PrivateUser{}, spotifyErr, nil
		}
	}

	// Decode response
	env.Logger.DebugContext(ctx, "Decoding spotify validation response")
	var user spotify.PrivateUser
	decoder := json.NewDecoder(res.Body)
	decoder.DisallowUnknownFields()
	defer res.Body.Close()
	err = hathrJson.DecodeJson(&user, decoder)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Error decoding response", slog.Any("error", err))
		return spotify.PrivateUser{}, spotify.Error{}, err
	}

	return user, spotify.Error{}, nil
}
