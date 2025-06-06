package models

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"hathr-backend/internal/database"
	spotifyModels "hathr-backend/internal/spotify/models"

	"github.com/google/uuid"
)

type Month string

var months = [12]Month{
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
	if !slices.Contains(months[:], fmtMonth) {
		return fmt.Errorf("Invalid month: %s", m)
	}
	return nil
}

func (m Month) Index() int {
	return slices.Index(months[:], Month(strings.ToLower(string(m))))
}

func GetMonth(m int) (Month, error) {
	if m <= 0 || m > len(months) {
		return Month(""), fmt.Errorf("Month must be >= 1 and < 12. Received : %d", m)
	}
	return months[m-1], nil
}

type MonthlyPlaylist struct {
	ID        uuid.UUID `json:"id" validate:"required"`
	UserID    uuid.UUID `json:"user_id" validate:"required"`
	Tracks    []string  `json:"tracks" validate:"required"`
	Year      int16     `json:"year" validate:"required,gte=2025"`
	Month     Month     `json:"month" validate:"required,validateFn"`
	Name      string    `json:"name" validate:"required"`
	CreatedAt time.Time `json:"created_at" validate:"required"`
}

type PublicUser struct {
	ID              uuid.UUID                `json:"id"`
	Username        string                   `json:"username"`
	DisplayName     string                   `json:"display_name"`
	CreatedAt       time.Time                `json:"created_at"`
	SpotifyUserData spotifyModels.PublicUser `json:"spotify_user_data"`
}

type FriendRequest struct {
	Friendship database.Friendship `json:"friendship"`
	User       PublicUser          `json:"user"`
}

type User struct {
	ID           uuid.UUID `json:"id"`
	DisplayName  string    `json:"display_name"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	RegisteredAt time.Time `json:"registered_at"`
	Role         string    `json:"role"`

	SpotifyUserID   string                   `json:"spotify_user_id"`
	SpotifyUserData spotifyModels.PublicUser `json:"spotify_user_data"`
	CreatedAt       time.Time                `json:"created_at"`
}
