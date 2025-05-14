// Package for spotify utility functions

package spotify

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	hathrEnv "hathr-backend/internal/env"
	hathrJson "hathr-backend/internal/json"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/zmb3/spotify/v2"
)

const spotifyBaseURL = "https://api.spotify.com/v1/"

// Authenticate a user via their bearer token
func AuthenticateUserToken(token string, env *hathrEnv.Env, ctx context.Context) (spotify.PrivateUser, spotify.Error, error) {

	// Create request
	env.Logger.DebugContext(ctx, "Creating spotify validation request")
	req, err := retryablehttp.NewRequest(http.MethodGet, spotifyBaseURL+"me", nil)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Error creating request", slog.Any("error", err))
		return spotify.PrivateUser{}, spotify.Error{}, err
	}
	req.Header.Set("Authorization", token)

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
		err = hathrJson.DecodeJson(&spotifyErr, res.Body)
		if err != nil {
			return spotify.PrivateUser{}, spotifyErr, nil
		}
	}

	// Decode response
	env.Logger.DebugContext(ctx, "Decoding spotify validation response")
	var user spotify.PrivateUser
	err = hathrJson.DecodeJson(&user, res.Body)
	if err != nil {
		return spotify.PrivateUser{}, spotify.Error{}, err
	}

	return user, spotify.Error{}, nil

}
