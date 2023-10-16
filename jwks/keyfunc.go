package jwks

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/worldline-go/auth/models"
)

type KeyFuncParser struct {
	KeyFunc func(token *jwt.Token) (interface{}, error)
}

func (j *KeyFuncParser) Keyfunc(token *jwt.Token) (interface{}, error) {
	if j.KeyFunc != nil {
		return j.KeyFunc(token)
	}

	return nil, fmt.Errorf("not implemented")
}

func (j *KeyFuncParser) ParseWithClaims(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
	// Parse the JWT.
	token, err := jwt.ParseWithClaims(tokenString, claims, j.Keyfunc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the JWT: %w", err)
	}

	// Check if the token is valid.
	if !token.Valid {
		return nil, models.ErrTokenInvalid
	}

	return token, nil
}
