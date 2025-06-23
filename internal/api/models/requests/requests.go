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

type CreatePlaylist struct {
	Hour  uint8        `json:"hour,omitempty" validate:"required_if=Type weekly,excluded_unless=Type weekly,gte=0,lte=23"`
	Day   uint8        `json:"day,omitempty" validate:"required_if=Type weekly,excluded_unless=Type weekly"`
	Year  uint16       `json:"year" validate:"required,gte=2025,lte=9999"`
	Month models.Month `json:"month" validate:"required"`

	Provider string `json:"provider" validate:"required,oneof=spotify"`
	Type     string `json:"type" validate:"required,oneof=weekly monthly"`
}

type GetUserPlaylists struct {
	UserID uuid.UUID `json:"user_id" validate:"required"`
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

type ReleasePlaylists struct {
	Day   uint8        `json:"day,omitempty" validate:"required_if=Type weekly,excluded_unless=Type weekly"`
	Year  uint16       `json:"year" validate:"required"`
	Month models.Month `json:"month" validate:"required"`

	Provider string `json:"provider" validate:"required,oneof=spotify"`
	Type     string `json:"type" validate:"required,oneof=weekly monthly"`
}

type CreatePlaylistImage struct {
	Day   uint8        `json:"day" validate:"required_if=Type weekly,excluded_unless=Type weekly"`
	Year  uint16       `json:"year" validate:"required"`
	Month models.Month `json:"month" validate:"required"`

	Type string `json:"type" validate:"required,oneof=weekly monthly"`
}
