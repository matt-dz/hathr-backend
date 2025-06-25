// Package for handler response structs

package responses

import (
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

type GetUserPlaylists struct {
	Playlists []models.PlaylistWithoutTracks `json:"playlists"`
}

type GetPlaylist struct {
	Playlist models.SpotifyPlaylist `json:"playlist" validate:"required"`
	User     models.PublicUser      `json:"user" validate:"required"`
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

type GetFriendPlaylists struct {
	Playlists []models.UserAndPlaylistWithoutTracks `json:"playlists"`
}

type ListRegisteredUsers struct {
	IDs  []uuid.UUID `json:"ids"`
	Next uuid.UUID   `json:"next,omitempty"`
}

type AddPlaylistToSpotify struct {
	URL string `json:"url"`
}
