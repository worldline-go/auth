package auth

import (
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

type Provider struct {
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
