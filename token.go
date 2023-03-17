package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// DefaultExpireDuration is the default duration to check if the access token is about to expire.
var DefaultExpireDuration = time.Second * 10

// IsRefreshNeed checks if the access token is about to expire.
func IsRefreshNeed(accessToken string) (bool, error) {
	claims := jwt.RegisteredClaims{}

	_, _, err := jwt.NewParser().ParseUnverified(accessToken, &claims)
	if err != nil {
		return false, err
	}

	return !claims.VerifyExpiresAt(time.Now().Add(DefaultExpireDuration), false), nil
}

func ParseUnverified(accessToken string) *jwt.MapClaims {
	claims := jwt.MapClaims{}

	_, _, err := jwt.NewParser().ParseUnverified(accessToken, &claims)
	if err != nil {
		return nil
	}

	return &claims
}
