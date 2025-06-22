package http

import "fmt"

type HTTPError struct {
	StatusCode int
	Status     string
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("Request Failed.\nStatus: %s. \nBody: %s", e.Status, e.Body)
}

func NewHTTPError(statusCode int, status, body string) error {
	return &HTTPError{
		StatusCode: statusCode,
		Status:     status,
		Body:       body,
	}
}
