package covers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"hathr-backend/internal/api/models"
	"hathr-backend/internal/env"
	hathrHttp "hathr-backend/internal/http"
	hathrJson "hathr-backend/internal/json"

	"github.com/hashicorp/go-retryablehttp"
)

const playlistCoverBucket = "playlist-covers"

type CreateMonthlyImageCoverParams struct {
	Month models.Month `json:"month"`
	Year  uint16       `json:"year"`
}

type CreateWeeklyImageCoverParams struct {
	Day1   uint8        `json:"day1"`
	Day2   uint8        `json:"day2"`
	Year1  uint16       `json:"year1"`
	Year2  uint16       `json:"year2"`
	Month1 models.Month `json:"month1"`
	Month2 models.Month `json:"month2"`
}

type CreateImageCoverResponse struct {
	URL string `json:"url"`
}

var generatorUrl = os.Getenv("IMAGE_GENERATOR_URL")
var generatorApiKey = os.Getenv("IMAGE_GENERATOR_API_KEY")

func CreateMonthlyImageCover(params CreateMonthlyImageCoverParams, env *env.Env) (CreateImageCoverResponse, error) {
	var response CreateImageCoverResponse
	if generatorUrl == "" {
		return response, fmt.Errorf("Please set IMAGE_GENERATOR_URL environment variable")
	}
	if generatorApiKey == "" {
		return response, fmt.Errorf("Please set IMAGE_GENERATOR_API_KEY environment variable")
	}

	// Create request
	endpoint := fmt.Sprintf("%s/monthly-playlist", generatorUrl)
	raw, err := json.Marshal(params)
	if err != nil {
		return response, err
	}
	req, err := retryablehttp.NewRequest(http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return response, err
	}
	req.Header.Add("X-API-Key", generatorApiKey)

	// Send request
	res, err := env.Http.Do(req)
	if err != nil {
		return response, err
	}
	defer res.Body.Close()
	if res.StatusCode > 299 {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return response, fmt.Errorf("failed to read body. status: %s. body: %w.", res.Status, err)
		}

		return response, hathrHttp.NewHTTPError(res.StatusCode, res.Status, string(body))
	}

	// Parse response
	decoder := json.NewDecoder(res.Body)
	decoder.DisallowUnknownFields()
	if err := hathrJson.DecodeJson(&response, decoder); err != nil {
		return response, err
	}

	return response, nil
}

func CreateWeeklyImageCover(params CreateWeeklyImageCoverParams, env *env.Env) (CreateImageCoverResponse, error) {
	var response CreateImageCoverResponse
	if generatorUrl == "" {
		return response, fmt.Errorf("Please set IMAGE_GENERATOR_URL environment variable")
	}
	if generatorApiKey == "" {
		return response, fmt.Errorf("Please set IMAGE_GENERATOR_API_KEY environment variable")
	}

	// Create request
	endpoint := fmt.Sprintf("%s/weekly-playlist", generatorUrl)
	raw, err := json.Marshal(params)
	if err != nil {
		return response, err
	}
	req, err := retryablehttp.NewRequest(http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return response, err
	}
	req.Header.Add("X-API-Key", generatorApiKey)

	// Send request
	res, err := env.Http.Do(req)
	if err != nil {
		return response, err
	}
	defer res.Body.Close()
	if res.StatusCode > 299 {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return response, fmt.Errorf("failed to read body. status: %s. body: %w.", res.Status, err)
		}

		return response, hathrHttp.NewHTTPError(res.StatusCode, res.Status, string(body))
	}

	// Parse response
	decoder := json.NewDecoder(res.Body)
	decoder.DisallowUnknownFields()
	if err := hathrJson.DecodeJson(&response, decoder); err != nil {
		return response, err
	}

	return response, nil
}

func MonthlyPlaylistCoverURL(month models.Month, year uint16) (string, error) {
	s3Url := os.Getenv("S3_URL")
	if s3Url == "" {
		return "", fmt.Errorf("Please set S3_URL environment variable")
	}
	return fmt.Sprintf("https://%s/%s/monthly/%d/%s.png", s3Url, playlistCoverBucket, year, string(month)), nil
}

func WeeklyPlaylistCoverURL(startMonth models.Month, startYear uint16, startDay uint8) (string, error) {
	s3Url := os.Getenv("S3_URL")
	if s3Url == "" {
		return "", fmt.Errorf("Please set S3_URL environment variable")
	}

	startDate := time.Date(int(startYear), time.Month(startMonth.Index()+1), int(startDay), 0, 0, 0, 0, time.Local)
	endDate := startDate.AddDate(0, 0, 7)
	startDateStr := fmt.Sprintf("%s_%d", startMonth, startDay)
	endDateStr := fmt.Sprintf("%s_%d", models.ToMonth(endDate.Month()), endDate.Day())
	return fmt.Sprintf("https://%s/%s/weekly/%d/%s/%s-%s.png", s3Url, playlistCoverBucket, endDate.Year(), models.ToMonth(endDate.Month()), startDateStr, endDateStr), nil
}
