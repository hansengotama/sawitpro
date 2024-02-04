package jwtutils

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"strings"
	"time"
)

type GenerateJwtInput struct {
	SecretKey        string
	UniqueIdentifier string
	ExpirationAt     time.Time
}

func GenerateJWT(input GenerateJwtInput) (string, error) {
	secretKey := []byte(input.SecretKey)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": input.UniqueIdentifier,
		"exp": input.ExpirationAt.Unix(),
		"iat": time.Now().Unix(),
	})

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ExtractToken(tokenWithBearer string) (string, error) {
	parts := strings.Fields(tokenWithBearer)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid token format")
	}

	return parts[1], nil
}
