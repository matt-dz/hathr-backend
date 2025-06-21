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
func DecodeJson(dst interface{}, decoder *json.Decoder) error {
	if err := decoder.Decode(dst); err != nil {
		return errors.Join(DecodeJSONError, err)
	}

	// Ensure no extra tokens after decoding
	if _, err := decoder.Token(); err != io.EOF {
		return errors.Join(DecodeJSONError, fmt.Errorf("Extraneous tokens found in request"))
	}
	return nil
}
