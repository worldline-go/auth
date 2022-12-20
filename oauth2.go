package auth

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

func (p *Provider) RoundTripperMust(ctx context.Context, transport http.RoundTripper) http.RoundTripper {
	roundTripper, err := p.RoundTripper(ctx, transport)
	if err != nil {
		panic(err)
	}

	return roundTripper
}

// RoundTripper returns a new RoundTripper that adds an OAuth2 Authorization header.
func (p *Provider) RoundTripper(ctx context.Context, transport http.RoundTripper) (http.RoundTripper, error) {
	activeProvider, err := p.ActiveProvider()
	if err != nil {
		return nil, err
	}

	src, err := activeProvider.Config()
	if err != nil {
		return nil, err
	}

	return &oauth2.Transport{
		Source: oauth2.ReuseTokenSource(nil, src.TokenSource(ctx)),
		Base:   transport,
	}, nil
}
