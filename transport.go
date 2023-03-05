package auth

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

// RoundTripperMust panic if RoundTripper return error.
func (p *Provider) RoundTripperMust(ctx context.Context, transport http.RoundTripper) http.RoundTripper {
	roundTripper, err := p.RoundTripper(ctx, transport)
	if err != nil {
		panic(err)
	}

	return roundTripper
}

// RoundTripper returns a new RoundTripper that adds an OAuth2 Transport.
//
// Uses active provider's ClientConfig.
func (p *Provider) RoundTripper(ctx context.Context, transport http.RoundTripper) (http.RoundTripper, error) {
	src, err := p.ActiveProvider().ClientConfig()
	if err != nil {
		return nil, err
	}

	// for noop provider
	if src == nil {
		return transport, nil
	}

	return &oauth2.Transport{
		Source: oauth2.ReuseTokenSource(nil, src.TokenSource(ctx)),
		Base:   transport,
	}, nil
}
