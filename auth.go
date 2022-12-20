package auth

import (
	"fmt"

	"github.com/worldline-go/auth/providers"
	"golang.org/x/oauth2/clientcredentials"
)

type Configurer interface {
	Config() (*clientcredentials.Config, error)
	// CertURL returns the certificate URL and the public key-id.
	CertURL() (string, error)
}

type Provider struct {
	Active   string              `cfg:"active"`
	Keycloak *providers.KeyCloak `cfg:"keycloak"`
}

// ActiveProvider returns the active provider or the first provider if none is active.
func (p *Provider) ActiveProvider() (Configurer, error) {
	if p.Active != "" {
		switch p.Active {
		case "keycloak":
			return p.Keycloak, nil
		default:
			return nil, fmt.Errorf("unknown provider: %s", p.Active)
		}
	}

	// select first non nil provider
	if p.Keycloak != nil {
		return p.Keycloak, nil
	}

	return nil, fmt.Errorf("no provider configured")
}

// SetActiveProvider return the provider with the given name as active without modifying the original provider.
func (p Provider) SetActiveProvider(name string) *Provider {
	p.Active = name

	return &p
}
