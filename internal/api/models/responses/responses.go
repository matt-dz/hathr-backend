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
	Playlist MonthlyPlaylist   `json:"playlist" validate:"required"`
	User     models.PublicUser `json:"user" validate:"required"`
}

type ListFriends struct {
	Friends []models.PublicUser `json:"friends"`
}

type ListFriendRequests struct {
	Outgoing []models.FriendRequest `json:"outgoing"`
	Incoming []models.FriendRequest `json:"incoming"`
}

type UserWithFriendship struct {
	User       models.PublicUser    `json:"user"`
	Friendship *database.Friendship `json:"friendship"`
}

type SearchUsers struct {
	Users []UserWithFriendship `json:"users"`
}

type UpdateFriendshipStatus struct {
	Friendship database.Friendship `json:"friendship"`
}
