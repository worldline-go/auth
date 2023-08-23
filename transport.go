package auth

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// Oauth2Transport wraps oauth2.Transport to suspend CancelRequest.
type Oauth2Transport struct {
	Transport oauth2.Transport
}

func (t *Oauth2Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.Transport.RoundTrip(req)
}

// RoundTripper returns a new RoundTripper that adds an OAuth2 Transport.
//
// Uses provider's ClientConfig.
func (p *ProviderExtra) RoundTripper(ctx context.Context, transport http.RoundTripper) (http.RoundTripper, error) {
	cfg, err := p.ClientConfig()
	if err != nil {
		return nil, err
	}

	return &Oauth2Transport{
		Transport: oauth2.Transport{
			Source: oauth2.ReuseTokenSource(nil, cfg.TokenSource(ctx)),
			Base:   transport,
		},
	}, nil
}

func (p *ProviderExtra) RoundTripperWrapper(cfg *clientcredentials.Config) func(ctx context.Context, transport http.RoundTripper) http.RoundTripper {
	return func(ctx context.Context, transport http.RoundTripper) http.RoundTripper {
		return &Oauth2Transport{
			Transport: oauth2.Transport{
				Source: oauth2.ReuseTokenSource(nil, cfg.TokenSource(ctx)),
				Base:   transport,
			},
		}
	}
}
