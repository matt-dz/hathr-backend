package models

import (
	"fmt"
	"slices"
	"strings"
)

type Month string

var months = []Month{
	"january",
	"february",
	"march",
	"april",
	"may",
	"june",
	"july",
	"august",
	"september",
	"october",
	"november",
	"december",
}

func (m Month) Validate() error {
	fmtMonth := Month(strings.ToLower(string(m)))
	if !slices.Contains(months, fmtMonth) {
		return fmt.Errorf("Invalid month: %s", m)
	}
	return nil
}

func GetMonth(m int) (Month, error) {
	if m < 0 || m >= len(months) {
		return Month(""), fmt.Errorf("Month must be >= 0 and < 12. Received : %d", m)
	}
	return months[m], nil
}
