// Package for handler response structs

package responses

import (
	"time"

	"hathr-backend/internal/api/models"
	"hathr-backend/internal/database"

	"github.com/google/uuid"
)

type LoginUser struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type UpsertUser struct {
	ID uuid.UUID `json:"id" validate:"required"`
}

type CreateMonthlyPlaylist struct {
	ID uuid.UUID `json:"id" validate:"required"`
}

type GetUserPlaylists struct {
	Playlists []database.MonthlyPlaylist `json:"playlists" validate:"required"`
}

type GetPlaylist struct {
	ID        uuid.UUID    `json:"uuid" validate:"required"`
	Tracks    []string     `json:"tracks" validate:"required"`
	Year      int          `json:"year" validate:"required,gte=2025"`
	Month     models.Month `json:"month" validate:"required"`
	Name      string       `json:"name" validate:"required"`
	CreatedAt time.Time    `json:"created_at" validate:"required"`
}
