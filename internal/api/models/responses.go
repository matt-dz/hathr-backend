package models

import (
	"hathr-backend/internal/database"
	"time"

	"github.com/google/uuid"
)

type UpsertUserResponse struct {
	ID uuid.UUID `json:"id" validate:"required"`
}

type CreateMonthlyPlaylistResponse struct {
	ID uuid.UUID `json:"id" validate:"required"`
}

type GetUserPlaylistsResposne struct {
	Playlists []database.MonthlyPlaylist `json:"playlists" validate:"required"`
}

type GetPlaylistResponse struct {
	ID        uuid.UUID `json:"uuid" validate:"required"`
	Tracks    []string  `json:"tracks" validate:"required"`
	Year      int       `json:"year" validate:"required,gte=2025"`
	Month     Month     `json:"month" validate:"required"`
	Name      string    `json:"name" validate:"required"`
	CreatedAt time.Time `json:"created_at" validate:"required"`
}
