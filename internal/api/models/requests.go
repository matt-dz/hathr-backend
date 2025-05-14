package models

import (
	"github.com/google/uuid"
)

type UpsertUserRequest struct {
	SpotifyUserID string `json:"spotify_user_id" validate:"required"`
	Email         string `json:"email" validate:"required,email"`
}

type CreateMonthlyPlaylist struct {
	UserID uuid.UUID `json:"id" validate:"required"`
	Tracks []string  `json:"tracks" validate:"required"`
	Year   int       `json:"year" validate:"required,gte=2025"`
	Month  string    `json:"month" validate:"required"`
	Name   string    `json:"name" validate:"required"`
}

type GetUserPlaylistsRequest struct {
	UserID uuid.UUID `json:"user_id" validate:"required"`
}

type GetPlaylistRequest struct {
	ID uuid.UUID `json:"id" validate:"required"`
}
