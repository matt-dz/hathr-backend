// Package for handler request structs

package requests

import (
	"hathr-backend/internal/api/models"

	"github.com/google/uuid"
)

type UpsertUser struct {
	SpotifyUserID string `json:"spotify_user_id" validate:"required"`
	Email         string `json:"email" validate:"required,email"`
}

type CreateMonthlyPlaylist struct {
	UserID uuid.UUID    `json:"id" validate:"required"`
	Tracks []string     `json:"tracks" validate:"required"`
	Year   int          `json:"year" validate:"required,gte=2025"`
	Month  models.Month `json:"month" validate:"required,validateFn"`
	Name   string       `json:"name" validate:"required"`
}

type GetUserPlaylists struct {
	UserID uuid.UUID `json:"user_id" validate:"required"`
}

type GetPlaylist struct {
	ID uuid.UUID `json:"id" validate:"required"`
}
