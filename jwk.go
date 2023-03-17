package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/rs/zerolog/log"
)

type ProviderExtra struct {
	InfProvider

	noop bool
}

func (p *ProviderExtra) IsNoop() bool {
	return p.noop
}

// JWTKeyFunc returns a jwt.Keyfunc.
//
// Need GetCertURL in provider.
func (p *ProviderExtra) JWTKeyFunc(opts ...OptionJWK) (InfJWTKeyFunc, error) {
	options := optionsJWK{
		refreshErrorHandler: func(err error) {
			log.Warn().Err(err).Msg("failed to refresh jwt.Keyfunc")
		},
		refreshInterval: time.Minute * 5,
		ctx:             context.Background(),
	}

	for _, opt := range opts {
		opt(&options)
	}

	if p.GetIntrospectURL() != "" {
		return &IntrospectJWTKey{
			URL:          p.GetIntrospectURL(),
			ClientID:     p.GetClientID(),
			ClientSecret: p.GetClientSecret(),
			Ctx:          options.ctx,
		}, nil
	}

	certURL := p.GetCertURL()
	if certURL == "" {
		return nil, fmt.Errorf("no cert URL")
	}

	keyOpts := keyfunc.Options{
		Ctx:                 options.ctx,
		RefreshErrorHandler: options.refreshErrorHandler,
		// RefreshRateLimit:    time.Minute * 5,
		RefreshInterval:   options.refreshInterval,
		RefreshUnknownKID: options.refreshUnknownKID,
		Client:            options.client,
	}

	jwks, err := keyfunc.Get(certURL, keyOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to get the JWKs from the given URL: %s; %w", certURL, err)
	}

	return &JWTKeyFunc{
		JWKS: jwks,
	}, nil
}
