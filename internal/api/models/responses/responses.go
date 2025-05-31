// Package for handler response structs

package responses

import (
	"time"

	"hathr-backend/internal/api/models"
	"hathr-backend/internal/database"

	"github.com/google/uuid"
)

type LoginUser struct {
	RefreshToken uuid.UUID `json:"refresh_token"`
}

type UpsertUser struct {
	ID uuid.UUID `json:"id" validate:"required"`
}

type CreateMonthlyPlaylist struct {
	ID uuid.UUID `json:"id" validate:"required"`
}

type MonthlyPlaylist struct {
	ID         uuid.UUID                   `json:"id"`
	UserID     uuid.UUID                   `json:"user_id"`
	Tracks     []map[string]interface{}    `json:"tracks"`
	Year       int                         `json:"year"`
	Month      models.Month                `json:"month"`
	Name       string                      `json:"name"`
	CreatedAt  time.Time                   `json:"created_at"`
	Visibility database.PlaylistVisibility `json:"visibility"`
}

type GetUserPlaylists struct {
	Playlists []MonthlyPlaylist `json:"playlists" validate:"required"`
}

type GetPlaylist struct {
	ID         uuid.UUID                   `json:"id"`
	UserID     uuid.UUID                   `json:"user_id"`
	Tracks     []map[string]interface{}    `json:"tracks"`
	Year       int                         `json:"year"`
	Month      models.Month                `json:"month"`
	Name       string                      `json:"name"`
	CreatedAt  time.Time                   `json:"created_at"`
	Visibility database.PlaylistVisibility `json:"visibility"`
}

type ListFriends struct {
	Friends []models.PublicUser `json:"friends"`
}

type ListFriendRequests struct {
	Requests []models.FriendRequest `json:"requests"`
}
