// Package for JSON utility functions

package json

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var DecodeJSONError = errors.New("DecodeJSONError")

// Decode a single JSON object
func DecodeJson(dst interface{}, r io.ReadCloser) error {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return errors.Join(DecodeJSONError, err)
	}
	defer r.Close()

	// Ensure no extra tokens after decoding
	var dud interface{}
	if err := decoder.Decode(&dud); err != io.EOF {
		return errors.Join(DecodeJSONError, fmt.Errorf("Extraneous tokens found in request"))
	}
	return nil
}
