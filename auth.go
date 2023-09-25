package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/worldline-go/auth/providers"
	"golang.org/x/oauth2/clientcredentials"
)

type InfProvider interface {
	ClientConfig() (*clientcredentials.Config, error)

	GetCertURL() string
	GetTokenURL() string
	GetTokenURLExternal() string
	GetAuthURL() string
	GetAuthURLExternal() string
	GetClientID() string
	GetClientIDExternal() string
	GetClientSecret() string
	GetClientSecretExternal() string
	GetScopes() []string
	GetIntrospectURL() string
}

type InfJWTKeyFunc interface {
	Keyfunc(token *jwt.Token) (interface{}, error)
	EndBackground()
	Parser(tokenString string, claims jwt.Claims) (*jwt.Token, error)
}

type InfProviderExtra interface {
	InfProvider
	// JWTKeyFunc returns the JWT key used to verify the token.
	JWTKeyFunc(opts ...OptionJWK) (InfJWTKeyFunc, error)
	IsNoop() bool
	NewOauth2Shared(ctx context.Context) (*OAuth2Shared, error)
	RoundTripper(ctx context.Context, transport http.RoundTripper) (http.RoundTripper, error)
	RoundTripperWrapper(cfg *clientcredentials.Config) func(ctx context.Context, transport http.RoundTripper) http.RoundTripper
}

type Provider struct {
	// Active is the name of the active provider, if empty the first provider is used.
	//
	// If set to "noop" the Noop provider is used.
	Active   string              `cfg:"active"`
	Keycloak *providers.KeyCloak `cfg:"keycloak"`
	Generic  *providers.Generic  `cfg:"generic"`
}

const (
	ProviderKeycloakKey = "keycloak"
	ProviderGenericKey  = "generic"
	ProviderNoopKey     = "noop"
)

func (p *Provider) providerGen(providerKey string) InfProviderExtra {
	switch strings.ToLower(providerKey) {
	case ProviderKeycloakKey:
		return &ProviderExtra{
			InfProvider: p.Keycloak,
		}
	case ProviderGenericKey:
		return &ProviderExtra{
			InfProvider: p.Generic,
		}
	case ProviderNoopKey:
		return Noop{}
	default:
		return nil
	}
}

// ActiveProvider returns the active provider or the first provider if none is active.
//
// Returns nil if no provider is configured.
func (p *Provider) ActiveProvider(opts ...OptionActiveProvider) (ret InfProviderExtra) {
	o := optionsActiveProvider{
		active: p.Active,
	}
	for _, opt := range opts {
		opt(&o)
	}

	if o.noop {
		return Noop{}
	}

	if o.active != "" {
		return p.providerGen(o.active)
	}

	// select first non nil provider
	if p.Keycloak != nil {
		return p.providerGen(ProviderKeycloakKey)
	}

	if p.Generic != nil {
		return p.providerGen(ProviderGenericKey)
	}

	return nil
}

// SetActiveProvider return the provider with the given name as active without modifying the original provider.
func (p Provider) SetActiveProvider(name string) *Provider {
	p.Active = name

	return &p
}
