package request

import (
	"context"
	"net/url"
)

type AuthorizationCodeConfig struct {
	Code            string
	RedirectURI     string
	NoClientIDParam bool

	AuthRequestConfig
}

// AuthorizationCode is a function to handle authorization code flow.
//
// Returns a byte array of the response body, if the response status code is 2xx.
func (a *Auth) AuthorizationCode(ctx context.Context, cfg AuthorizationCodeConfig) ([]byte, error) {
	uValues := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {cfg.Code},
		"redirect_uri": {cfg.RedirectURI},
	}

	if !cfg.NoClientIDParam {
		uValues.Add("client_id", cfg.ClientID)
	}

	return a.AuthRequest(ctx, uValues, cfg.AuthRequestConfig)
}
