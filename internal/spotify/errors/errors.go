package errors

import "fmt"

type SpotifyError struct {
	StatusCode int
	Status     string
	Message    string
}

func (e *SpotifyError) Error() string {
	return fmt.Sprintf("%s - %s", e.Status, e.Message)
}
