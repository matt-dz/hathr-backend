package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func CreateJWT(userID string, admin bool, privateKeyBytes []byte) (string, error) {

	claims := jwt.MapClaims{
		"sub":   userID,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
		"admin": admin,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return "", err
	}

	signed, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return signed, nil
}
