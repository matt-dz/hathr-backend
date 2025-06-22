package covers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"hathr-backend/internal/api/models"
	"hathr-backend/internal/env"
	hathrHttp "hathr-backend/internal/http"
	hathrJson "hathr-backend/internal/json"

	"github.com/hashicorp/go-retryablehttp"
)

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

func CreateMonthlyImageCover(params CreateMonthlyImageCoverParams, env *env.Env) (CreateImageCoverResponse, error) {
	var response CreateImageCoverResponse
	if generatorUrl == "" {
		return response, fmt.Errorf("Please set IMAGE_GENERATOR_URL environment variable")
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
