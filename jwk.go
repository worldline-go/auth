package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/rs/zerolog/log"
)

// GetJwks returns a jwt.Keyfunc.
func (p *Provider) GetJwks(ctx context.Context, opts ...OptionJWK) (*keyfunc.JWKS, error) {
	options := optionsJWK{
		refreshErrorHandler: func(err error) {
			log.Warn().Err(err).Msg("failed to refresh jwt.Keyfunc")
		},
	}

	for _, opt := range opts {
		opt(&options)
	}

	activeProvider, err := p.ActiveProvider()
	if err != nil {
		return nil, err
	}

	certURL, err := activeProvider.CertURL()
	if err != nil {
		return nil, err
	}

	keyOpts := keyfunc.Options{
		Ctx:                 ctx,
		RefreshErrorHandler: options.refreshErrorHandler,
		// RefreshRateLimit:    time.Minute * 5,
		RefreshInterval:   time.Minute * 5,
		RefreshUnknownKID: false,
	}

	jwks, err := keyfunc.Get(certURL, keyOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to get the JWKs from the given URL: %s; %w", certURL, err)
	}

	return jwks, nil
}
