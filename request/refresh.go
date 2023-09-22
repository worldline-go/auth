package request

import (
	"context"
	"net/url"
	"strings"
)

type RefreshTokenConfig struct {
	RefreshToken string

	AuthRequestConfig
}

// RefreshToken is a function to handle refresh token flow.
//
// Returns a byte array of the response body, if the response status code is 2xx.
func (a *Auth) RefreshToken(ctx context.Context, cfg RefreshTokenConfig) ([]byte, error) {
	uValues := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {cfg.ClientID},
		"refresh_token": {cfg.RefreshToken},
	}

	if len(cfg.Scopes) > 0 {
		uValues.Add("scope", strings.Join(cfg.Scopes, " "))
	}

	return a.AuthRequest(ctx, uValues, cfg.AuthRequestConfig)
}
