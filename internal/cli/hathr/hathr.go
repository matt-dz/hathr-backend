package hathr

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"hathr-backend/internal/api/models"
	"hathr-backend/internal/api/models/requests"
	"hathr-backend/internal/api/models/responses"
	"hathr-backend/internal/env"
	hathrHttp "hathr-backend/internal/http"
	hathrJson "hathr-backend/internal/json"
	"hathr-backend/internal/logging"

	"github.com/google/uuid"
	"github.com/hashicorp/go-retryablehttp"
)

var backendUrl = os.Getenv("HATHR_BACKEND_URL")

func init() {
	if backendUrl == "" {
		log.Fatal("Please set HATHR_BACKEND_URL environment variable")
	}
}

func AdminLogin(env *env.Env) (string, error) {
	hathrUsername := os.Getenv("HATHR_USERNAME")
	hathrPassword := os.Getenv("HATHR_PASSWORD")
	if hathrUsername == "" || hathrPassword == "" {
		return "", fmt.Errorf("Please set HATHR_BACKEND_URL, HATHR_USERNAME, and HATHR_PASSWORD environment variables")
	}

	requestBody := requests.AdminLogin{
		Username: hathrUsername,
		Password: hathrPassword,
	}
	rawBody, err := json.Marshal(requestBody)
	if err != nil {
		return "", err
	}

	res, err := env.Http.Post(fmt.Sprintf("%s/api/login/admin", backendUrl), "application/json", bytes.NewReader(rawBody))
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			env.Logger.Error("Failed to read response body", slog.Any("error", err))
			return "", errors.Join(err, hathrHttp.NewHTTPError(res.StatusCode, res.Status, ""))
		}
		return "", hathrHttp.NewHTTPError(res.StatusCode, res.Status, string(body))
	}

	var loginResponse responses.LoginUser
	decoder := json.NewDecoder(res.Body)
	decoder.DisallowUnknownFields()
	if err := hathrJson.DecodeJson(&loginResponse, decoder); err != nil {
		return "", err
	}
	return res.Header.Get("Authorization"), nil
}

func ListUsers(bearerToken string, next uuid.UUID, limit uint, env *env.Env) (responses.ListRegisteredUsers, error) {

	var response responses.ListRegisteredUsers

	// Building request
	req, err := retryablehttp.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/users?limit=%d&after=%s", backendUrl, limit, next.String()), nil)
	if err != nil {
		return response, err
	}
	req.Header.Add("Authorization", bearerToken)

	// Sending request
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
	decoder := json.NewDecoder(res.Body)
	decoder.DisallowUnknownFields()
	if err := hathrJson.DecodeJson(&response, decoder); err != nil {
		return response, err
	}
	return response, nil
}

func CreateMonthlyPlaylist(currentTime time.Time, userID uuid.UUID, bearerToken string, env *env.Env) error {
	ctx := logging.AppendCtx(context.Background(), slog.String("user_id", userID.String()))
	previousMonth := currentTime.AddDate(0, -1, 0)

	// Create request
	requestBody := requests.CreatePlaylist{
		Month:    models.ToMonth(previousMonth.Month()),
		Year:     uint16(previousMonth.Year()),
		Provider: "spotify",
		Type:     "monthly",
	}
	rawBody, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}
	req, err := retryablehttp.NewRequest(http.MethodPost, fmt.Sprintf("%s/api/playlist/%s/spotify", backendUrl, userID.String()), bytes.NewReader(rawBody))
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", bearerToken)

	// Send request
	res, err := env.Http.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()
	if res.StatusCode > 299 {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Failed to read response body", slog.Any("error", err))
			return errors.Join(err, hathrHttp.NewHTTPError(res.StatusCode, res.Status, string(body)))
		}
		return hathrHttp.NewHTTPError(res.StatusCode, res.Status, string(body))
	}

	return nil
}

func CreateWeeklyPlaylist(weekEnd time.Time, userID uuid.UUID, bearerToken string, env *env.Env) error {
	ctx := logging.AppendCtx(context.Background(), slog.String("user_id", userID.String()))
	weekStart := weekEnd.AddDate(0, 0, -7)

	// Create request
	env.Logger.DebugContext(ctx, "Creating request")
	requestBody := requests.CreatePlaylist{
		Hour:     uint8(weekStart.Hour()),
		Day:      uint8(weekStart.Day()),
		Year:     uint16(weekStart.Year()),
		Month:    models.ToMonth(weekStart.Month()),
		Provider: "spotify",
		Type:     "weekly",
	}
	rawBody, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}
	req, err := retryablehttp.NewRequest(http.MethodPost, fmt.Sprintf("%s/api/playlist/%s/spotify", backendUrl, userID.String()), bytes.NewReader(rawBody))
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", bearerToken)

	// Send request
	res, err := env.Http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode > 299 {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Failed to read response body", slog.Any("error", err))
			return errors.Join(err, hathrHttp.NewHTTPError(res.StatusCode, res.Status, ""))
		}
		return hathrHttp.NewHTTPError(res.StatusCode, res.Status, string(body))
	}

	return nil
}

func ReleaseWeeklyPlaylist(weekEnd time.Time, bearerToken string, env *env.Env) error {

	// Build request
	weekStart := weekEnd.AddDate(0, 0, -7)
	requestBody := requests.ReleasePlaylists{
		Day:      uint8(weekStart.Day()),
		Year:     uint16(weekStart.Year()),
		Month:    models.ToMonth(weekStart.Month()),
		Type:     "weekly",
		Provider: "spotify",
	}
	rawBody, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}
	req, err := retryablehttp.NewRequest(http.MethodPatch, fmt.Sprintf("%s/api/release-playlists", backendUrl), bytes.NewReader(rawBody))
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", bearerToken)

	// Send request
	res, err := env.Http.Do(req)
	if err != nil {
		return err
	}

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

func ReleaseMonthlyPlaylist(currentTime time.Time, bearerToken string, env *env.Env) error {
	// Build request
	previousMonth := currentTime.AddDate(0, -1, 0)
	requestBody := requests.ReleasePlaylists{
		Year:     uint16(previousMonth.Year()),
		Month:    models.ToMonth(previousMonth.Month()),
		Type:     "monthly",
		Provider: "spotify",
	}
	rawBody, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}
	req, err := retryablehttp.NewRequest(http.MethodPatch, fmt.Sprintf("%s/api/release-playlists", backendUrl), bytes.NewReader(rawBody))
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", bearerToken)

	// Send request
	res, err := env.Http.Do(req)
	if err != nil {
		return err
	}

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

func AggregatePlays(userID uuid.UUID, after time.Time, bearerToken string, env *env.Env) error {
	ctx := logging.AppendCtx(context.Background(), slog.String("user_id", userID.String()))

	// Building request
	env.Logger.DebugContext(ctx, "Building request")
	url := fmt.Sprintf("%s/api/users/%s/plays/spotify", backendUrl, userID.String())
	requestBody := requests.UpdateSpotifyPlays{
		After: after,
	}
	rawBody, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}
	req, err := retryablehttp.NewRequest(http.MethodPost, url, bytes.NewReader(rawBody))
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", bearerToken)

	// Send request
	env.Logger.DebugContext(ctx, "Sending update plays request")
	res, err := env.Http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode > 299 {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			env.Logger.ErrorContext(ctx, "Failed to read response body", slog.Any("error", err))
			return errors.Join(err, hathrHttp.NewHTTPError(res.StatusCode, res.Status, ""))
		}
		return hathrHttp.NewHTTPError(res.StatusCode, res.Status, string(body))
	}

	env.Logger.DebugContext(ctx, "Successfully updated plays for user")
	return nil
}

func CreateWeeklyPlaylistCover(day uint8, month time.Month, year uint16, bearerToken string, env *env.Env) error {
	// Build request
	url := fmt.Sprintf("%s/api/playlist-cover", backendUrl)
	requestBody := requests.CreatePlaylistImage{
		Type:  "weekly",
		Day:   day,
		Year:  year,
		Month: models.ToMonth(month),
	}
	rawBody, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}
	req, err := retryablehttp.NewRequest(http.MethodPost, url, bytes.NewReader(rawBody))
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", bearerToken)

	// Send request
	res, err := env.Http.Do(req)
	if err != nil {
		return err
	}
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

func CreateMonthlyPlaylistCover(month time.Month, year uint16, bearerToken string, env *env.Env) error {
	// Build request
	url := fmt.Sprintf("%s/api/playlist-cover", backendUrl)
	requestBody := requests.CreatePlaylistImage{
		Type:  "monthly",
		Year:  year,
		Month: models.ToMonth(month),
	}
	rawBody, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}
	req, err := retryablehttp.NewRequest(http.MethodPost, url, bytes.NewReader(rawBody))
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", bearerToken)

	// Send request
	res, err := env.Http.Do(req)
	if err != nil {
		return err
	}
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
