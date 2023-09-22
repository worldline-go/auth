package request

import (
	"context"
	"net/url"
	"strings"
)

type ClientCredentialsConfig struct {
	RefreshToken string

	// EndpointParams specifies additional parameters for requests to the token endpoint.
	EndpointParams url.Values

	AuthRequestConfig
}

// RefreshToken is a function to handle refresh token flow.
//
// Returns a byte array of the response body, if the response status code is 2xx.
func (a *Auth) ClientCredentials(ctx context.Context, cfg ClientCredentialsConfig) ([]byte, error) {
	uValues := url.Values{
		"grant_type": {"client_credentials"},
	}
	if len(cfg.Scopes) > 0 {
		uValues.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	for k, p := range cfg.EndpointParams {
		uValues[k] = p
	}

	return a.AuthRequest(ctx, uValues, cfg.AuthRequestConfig)
}
