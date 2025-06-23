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

type SpotifyPlaylistTrack struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Artists  []string `json:"artists"`
	ImageURL string   `json:"image_url"`
	Href     string   `json:"href"`
}

type SpotifyPlaylist struct {
	Day        uint8                       `json:"day"`
	Year       uint16                      `json:"year"`
	Month      Month                       `json:"month"`
	Visibility database.PlaylistVisibility `json:"visibility"`
	CreatedAt  time.Time                   `json:"created_at"`
	Tracks     []SpotifyPlaylistTrack      `json:"tracks"`
	ID         uuid.UUID                   `json:"id"`
	UserID     uuid.UUID                   `json:"user_id"`
	Name       string                      `json:"name"`
	Type       string                      `json:"type"`
	ImageURL   string                      `json:"image_url"`
}

type PlaylistWithoutTracks struct {
	Day        uint8                       `json:"day"`
	Year       uint16                      `json:"year"`
	NumTracks  uint16                      `json:"num_tracks"`
	Month      Month                       `json:"month"`
	Visibility database.PlaylistVisibility `json:"visibility"`
	CreatedAt  time.Time                   `json:"created_at"`
	ID         uuid.UUID                   `json:"id"`
	UserID     uuid.UUID                   `json:"user_id"`
	Name       string                      `json:"name"`
	Type       string                      `json:"type"`
	ImageURL   string                      `json:"image_url"`
}

type PublicUser struct {
	ID              uuid.UUID                 `json:"id"`
	Username        string                    `json:"username"`
	DisplayName     string                    `json:"display_name"`
	CreatedAt       time.Time                 `json:"created_at"`
	ImageURL        *string                   `json:"image_url"`
	SpotifyUserData *spotifyModels.PublicUser `json:"spotify_user_data"`
}

type UserProfile struct {
	ID              uuid.UUID                 `json:"id"`
	Username        string                    `json:"username"`
	DisplayName     string                    `json:"display_name"`
	Email           string                    `json:"email"`
	CreatedAt       time.Time                 `json:"created_at"`
	ImageURL        *string                   `json:"image_url"`
	SpotifyUserData *spotifyModels.PublicUser `json:"spotify_user_data"`
}

type UserAndPlaylistWithoutTracks struct {
	User     PublicUser            `json:"user"`
	Playlist PlaylistWithoutTracks `json:"playlist"`
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
