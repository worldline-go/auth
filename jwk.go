package auth

import (
	"fmt"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/worldline-go/auth/models"
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
//
// If introspect is true, the introspect endpoint is used to verify the token.
// Use Parser function for introspect, not keyfunc.
func (p *ProviderExtra) JWTKeyFunc(opts ...OptionJWK) (models.InfKeyFuncParser, error) {
	option := GetOptionJWK(opts...)

	if option.Introspect {
		return &IntrospectJWTKey{
			URL:          p.GetIntrospectURL(),
			ClientID:     p.GetClientID(),
			ClientSecret: p.GetClientSecret(),
			Ctx:          option.Ctx,
		}, nil
	}

	certURL := p.GetCertURL()
	if certURL == "" {
		return nil, fmt.Errorf("no cert URL")
	}

	keyOpts := MapOptionKeyfunc(option)
	jwksKeyFunc, err := keyfunc.Get(certURL, keyOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to get the JWKs from the given URL: %s; %w", certURL, err)
	}

	return &JwkKeyFuncParse{
		KeyFunc: jwksKeyFunc.Keyfunc,
	}, nil
}
