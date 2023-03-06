package auth

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

// RoundTripperMust panic if RoundTripper return error.
func RoundTripperMust(roundTripper http.RoundTripper, err error) http.RoundTripper {
	if err != nil {
		panic(err)
	}

	return roundTripper
}

// RoundTripper returns a new RoundTripper that adds an OAuth2 Transport.
//
// Uses active provider's ClientConfig.
func (p *ProviderExtra) RoundTripper(ctx context.Context, transport http.RoundTripper) (http.RoundTripper, error) {
	src, err := p.ClientConfig()
	if err != nil {
		return nil, err
	}

	return &oauth2.Transport{
		Source: oauth2.ReuseTokenSource(nil, src.TokenSource(ctx)),
		Base:   transport,
	}, nil
}
