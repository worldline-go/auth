package request

import (
	"context"
	"net/url"
	"strings"
)

type PassswordConfig struct {
	Username string
	Password string

	Scopes []string

	AuthRequestConfig
}

func (a *Auth) Password(ctx context.Context, cfg PassswordConfig) ([]byte, error) {
	uValues := url.Values{
		"grant_type": {"password"},
		"username":   {cfg.Username},
		"password":   {cfg.Password},
	}
	if len(cfg.Scopes) > 0 {
		uValues.Set("scope", strings.Join(cfg.Scopes, " "))
	}

	return a.AuthRequest(ctx, uValues, cfg.AuthRequestConfig)
}
