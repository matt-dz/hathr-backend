// Package for handler request structs

package requests

import (
	"hathr-backend/internal/api/models"
	"hathr-backend/internal/database"
	"time"

	"github.com/google/uuid"
)

type UpsertUser struct {
	SpotifyUserID string `json:"spotify_user_id" validate:"required"`
}

type CreateMonthlyPlaylist struct {
	Year     int             `json:"year" validate:"required,gte=2025"`
	Month    models.Month    `json:"month" validate:"required,validateFn"`
	Provider models.Provider `json:"provider" validate:"required,validateFn"`
}

type GetUserPlaylists struct {
	UserID uuid.UUID `json:"user_id" validate:"required"`
}

type GetPlaylist struct {
	ID uuid.UUID `json:"id" validate:"required"`
}

type RefreshSession struct {
	RefreshToken uuid.UUID `json:"refresh_token" validate:"required"`
}

type UpdateVisibility struct {
	Visibility database.PlaylistVisibility `json:"visibility" validate:"required,oneof=public friends private"`
}

type CreateFriendRequest struct {
	UserID uuid.UUID `json:"user_id" validate:"required"`
}

type UpdateFriendshipStatus struct {
	Status string `json:"status" validate:"required,oneof=accepted"`
}

type CompleteSignup struct {
	Username string `json:"username" validate:"required"`
}

type UpdateUserProfile struct {
	Username    *string `json:"username"`
	Email       *string `json:"email"`
	DisplayName *string `json:"display_name"`
}

type AdminLogin struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type UpdateSpotifyPlays struct {
	After time.Time `json:"after" validate:"required"`
}
