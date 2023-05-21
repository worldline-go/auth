package auth

import (
	"fmt"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
)

type JWTKeyFunc struct {
	*keyfunc.JWKS
}

func (j *JWTKeyFunc) Parser(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
	// Parse the JWT.
	token, err := jwt.ParseWithClaims(tokenString, claims, j.Keyfunc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the JWT: %w", err)
	}

	// Check if the token is valid.
	if !token.Valid {
		return nil, ErrTokenInvalid
	}

	return token, nil
}
