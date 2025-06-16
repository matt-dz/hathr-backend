package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type LoginRequest struct {
	Code         string `json:"code" validate:"required"`
	CodeVerifier string `json:"code_verifier" validate:"required"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type ExplicitContent struct {
	FilterEnabled bool `json:"filter_enabled"`
	FilterLocked  bool `json:"filter_locked"`
}

type ExternalURLs struct {
	Spotify string `json:"spotify"`
}

type Followers struct {
	Href  string `json:"href"`
	Total int    `json:"total"`
}

type Image struct {
	URL    string `json:"url"`
	Height int    `json:"height"`
	Width  int    `json:"width"`
}

type User struct {
	Country      string       `json:"country"`
	DisplayName  string       `json:"display_name"`
	Email        string       `json:"email"`
	ExternalURLs ExternalURLs `json:"external_urls"`
	Followers    Followers    `json:"followers"`
	Href         string       `json:"href"`
	ID           string       `json:"id"`
	Images       []Image      `json:"images"`
	Product      string       `json:"product"`
	Type         string       `json:"type"`
	URI          string       `json:"uri"`
}

type PublicUser struct {
	DisplayName  string       `json:"display_name"`
	ExternalURLs ExternalURLs `json:"external_urls"`
	ID           string       `json:"id"`
	Images       []Image      `json:"images"`
	URI          string       `json:"uri"`
}

type PlaylistWithoutTracks struct {
	ID         uuid.UUID `json:"id"`
	UserID     uuid.UUID `json:"user_id"`
	NumTracks  int       `json:"num_tracks"`
	Type       string    `json:"type"`
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"created_at"`
	Visibility string    `json:"visibility"`
	Year       int       `json:"year"`
	Week       *int      `json:"week"`
	Month      *int      `json:"month"`
}

type Artist struct {
	ExternalURLs ExternalURLs `json:"external_urls"`
	Followers    Followers    `json:"followers"`
	Genres       []string     `json:"genres"`
	Href         string       `json:"href"`
	ID           string       `json:"id"`
	Images       []Image      `json:"images"`
	Name         string       `json:"name"`
	Popularity   int          `json:"popularity"`
	Type         string       `json:"type"`
	URI          string       `json:"uri"`
}

type SimplifiedArtist struct {
	ExternalURLs ExternalURLs `json:"external_urls"`
	Href         string       `json:"href"`
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Type         string       `json:"type"`
	URI          string       `json:"uri"`
}

type RefreshTokenRequest struct {
	GrantType    string `json:"grant_type"`
	RefreshToken string `json:"refresh_token"`
	ClientID     string `json:"client_id"`
}

type RefreshTokenResponse struct {
	AccessToken  string  `json:"access_token"`
	TokenType    string  `json:"token_type"`
	Scope        string  `json:"scope"`
	ExpiresIn    int     `json:"expires_in"`
	RefreshToken *string `json:"refresh_token"`
}

type TopArtistsResponse struct {
	Href     string   `json:"href"`
	Limit    int      `json:"limit"`
	Next     string   `json:"next"`
	Offset   int      `json:"offset"`
	Previous string   `json:"previous"`
	Total    int      `json:"total"`
	Items    []Artist `json:"items"`
}

type Restrictions struct {
	Reason string `json:"reason"`
}

type Album struct {
	AlbumType            string             `json:"album_type"`
	TotalTracks          int                `json:"total_tracks"`
	AvailableMarkets     []string           `json:"available_markets"`
	ExternalURLs         ExternalURLs       `json:"external_urls"`
	Href                 string             `json:"href"`
	ID                   string             `json:"id"`
	Images               []Image            `json:"images"`
	Name                 string             `json:"name"`
	ReleaseDate          string             `json:"release_date"`
	ReleaseDatePrecision string             `json:"release_date_precision"`
	Restrictions         Restrictions       `json:"restrictions"`
	Type                 string             `json:"type"`
	URI                  string             `json:"uri"`
	Artists              []SimplifiedArtist `json:"artists"`
}

type ExternalIDs struct {
	Isrc string `json:"isrc"`
	Ean  string `json:"ean"`
	Upc  string `json:"upc"`
}

type Track struct {
	Album            Album              `json:"album"`
	Artists          []SimplifiedArtist `json:"artists"`
	AvailableMarkets []string           `json:"available_markets"`
	DiscNumber       int                `json:"disc_number"`
	DurationMs       int                `json:"duration_ms"`
	Explicit         bool               `json:"explicit"`
	ExternalIDs      ExternalIDs        `json:"external_ids"`
	ExternalURLs     ExternalURLs       `json:"external_urls"`
	ID               string             `json:"id"`
	IsPlayable       bool               `json:"is_playable"`
	Restrictions     Restrictions       `json:"restrictions"`
	Name             string             `json:"name"`
	Popularity       int8               `json:"popularity"`
	PreviewURL       *string            `json:"preview_url"`
	TrackNumber      int                `json:"track_number"`
	Type             string             `json:"type"`
	URI              string             `json:"uri"`
	IsLocal          bool               `json:"is_local"`
}

type TopTracksResponse struct {
	Href     string  `json:"href"`
	Limit    int     `json:"limit"`
	Next     *string `json:"next"`
	Offset   int     `json:"offset"`
	Previous string  `json:"previous"`
	Total    int     `json:"total"`
	Items    []Track `json:"items"`
}

type Cursors struct {
	After  string `json:"after"`
	Before string `json:"before"`
}

type PlayHistory struct {
	Track    Track     `json:"track"`
	PlayedAt time.Time `json:"played_at"`
	Context  Context   `json:"context"`
}

type Context struct {
	Type         string       `json:"type"`
	Href         string       `json:"href"`
	ExternalURLs ExternalURLs `json:"external_urls"`
	URI          string       `json:"uri"`
}

type RecentlyPlayedTracksResponse struct {
	Href    string        `json:"href"`
	Limit   int           `json:"limit"`
	Next    *string       `json:"next"`
	Cursors Cursors       `json:"cursors"`
	Total   int           `json:"total"`
	Items   []PlayHistory `json:"items"`
	Context Context       `json:"context"`
}

type SpotifyTrackInput struct {
	ID         string      `db:"id"`
	Name       string      `db:"name"`
	Artists    []string    `db:"artists"`
	Popularity int         `db:"popularity"`
	ImageURL   pgtype.Text `db:"image_url"`
	Raw        []byte      `db:"raw"`
}
