package auth

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

// RoundTripper returns a new RoundTripper that adds an OAuth2 Transport.
//
// Uses provider's ClientConfig.
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
