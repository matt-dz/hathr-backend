package models

type LoginRequest struct {
	GrantType    string `json:"grant_type" validate:"required"`
	Code         string `json:"code" validate:"required"`
	RedirectURI  string `json:"redirect_uri" validate:"required,uri"`
	ClientID     string `json:"client_id" validate:"required"`
	CodeVerifier string `json:"code_verifier" validate:"required"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}
