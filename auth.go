package auth

import (
	"context"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
	"github.com/worldline-go/auth/providers"
	"golang.org/x/oauth2/clientcredentials"
)

type InfProvider interface {
	ClientConfig() (*clientcredentials.Config, error)

	GetCertURL() string
	GetTokenURL() string
	GetAuthURL() string
	GetClientID() string
	GetClientSecret() string
}

type InfJWTKeyFunc interface {
	Keyfunc(token *jwt.Token) (interface{}, error)
	EndBackground()
	Parser(tokenString string, claims jwt.Claims) (*jwt.Token, error)
}

type InfProviderExtra interface {
	InfProvider
	// JWTKeyFunc returns the JWT key used to verify the token.
	JWTKeyFunc(ctx context.Context, opts ...OptionJWK) (InfJWTKeyFunc, error)
	IsNoop() bool
	RoundTripper(ctx context.Context, transport http.RoundTripper) (http.RoundTripper, error)
}

type Provider struct {
	// Active is the name of the active provider, if empty the first provider is used.
	//
	// If set to "noop" the Noop provider is used.
	Active   string              `cfg:"active"`
	Keycloak *providers.KeyCloak `cfg:"keycloak"`
}

// ActiveProvider returns the active provider or the first provider if none is active.
//
// Returns nil if no provider is configured.
func (p *Provider) ActiveProvider(opts ...OptionActiveProvider) (ret InfProviderExtra) {
	var o optionsActiveProvider
	for _, opt := range opts {
		opt(&o)
	}

	if o.noop {
		return Noop{}
	}

	if p.Active != "" {
		switch p.Active {
		case "keycloak":
			return &ProviderExtra{
				InfProvider: p.Keycloak,
			}
		case "noop":
			return Noop{}
		default:
			return nil
		}
	}

	// select first non nil provider
	if p.Keycloak != nil {
		return &ProviderExtra{
			InfProvider: p.Keycloak,
		}
	}

	return nil
}

// SetActiveProvider return the provider with the given name as active without modifying the original provider.
func (p Provider) SetActiveProvider(name string) *Provider {
	p.Active = name

	return &p
}
