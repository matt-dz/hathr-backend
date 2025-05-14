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

func ValidateUserProfile(token string, env *hathrEnv.Env, ctx context.Context) (spotify.PrivateUser, error) {
	env.Logger.DebugContext(ctx, "Creating spotify validation request")
	req, err := retryablehttp.NewRequest(http.MethodGet, spotifyBaseURL+"me", nil)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Error creating request", slog.Any("error", err))
		return spotify.PrivateUser{}, err
	}
	req.Header.Set("Authorization", token)

	env.Logger.DebugContext(ctx, "Sending request")
	client := retryablehttp.NewClient()
	client.RetryWaitMax = time.Second * 10
	client.Logger = env.Logger
	res, err := client.Do(req)
	if err != nil {
		env.Logger.ErrorContext(ctx, "Request failed", slog.Any("error", err))
		return spotify.PrivateUser{}, err
	}

	env.Logger.DebugContext(ctx, "Decoding spotify validation response")
	var user spotify.PrivateUser
	err = hathrJson.DecodeJson(&user, res.Body)
	if err != nil {
		return spotify.PrivateUser{}, err
	}

	return user, nil
}
