package providers

import (
	"fmt"
	"net/url"
	"path"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type KeyCloak struct {
	// Extra settings for clients.
	// ClientID is the application's ID.
	ClientID string `cfg:"client_id"`

	// ClientSecret is the application's secret.
	ClientSecret string `cfg:"client_secret"`

	// Scope specifies optional requested permissions.
	Scopes []string `cfg:"scopes"`

	// End of extra settings for clients.

	// CertURL is the resource server's public key URL.
	//
	// BaseURL and REALM are used to construct the CertURL.
	CertURL string `cfg:"cert_url"`

	// AuthURL is the resource server's authorization endpoint
	// use for redirection to login page.
	//
	// BaseURL and REALM are used to construct the AuthURL.
	AuthURL string `cfg:"auth_url"`

	// TokenURL is the resource server's token endpoint
	// URL. This is a constant specific to each server.
	//
	// BaseURL and REALM are used to construct the TokenURL.
	TokenURL string `cfg:"token_url"`

	// BaseURL is the resource server's base URL like https://keycloak:8080.
	//
	// If your server has auth path set like https://keycloak:8080/auth/
	BaseURL string `cfg:"base_url"`
	// Realm is the resource server's realm like master.
	Realm string `cfg:"realm"`
}

func (p *KeyCloak) GetCertURL() string {
	_ = p.setCertURL()

	return p.CertURL
}

func (p *KeyCloak) GetAuthURL() string {
	_ = p.setAuthURL()

	return p.AuthURL
}

func (p *KeyCloak) GetTokenURL() string {
	_ = p.setTokenURL()

	return p.TokenURL
}

func (p *KeyCloak) GetClientID() string {
	return p.ClientID
}

func (p *KeyCloak) GetClientSecret() string {
	return p.ClientSecret
}

func (p *KeyCloak) ClientConfig() (*clientcredentials.Config, error) {
	tokenURL := p.GetTokenURL()
	if tokenURL == "" {
		return nil, fmt.Errorf("tokenURL empty")
	}

	return &clientcredentials.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		TokenURL:     p.TokenURL,
		Scopes:       p.Scopes,
		AuthStyle:    oauth2.AuthStyleInHeader,
	}, nil
}

func (p *KeyCloak) setTokenURL() error {
	if p.TokenURL != "" {
		return nil
	}

	if p.BaseURL == "" || p.Realm == "" {
		return fmt.Errorf("base_url and realm are required")
	}

	parsedURL, err := url.Parse(p.BaseURL)
	if err != nil {
		return fmt.Errorf("base_url is invalid: %s", err)
	}

	parsedURL.Path = path.Join(parsedURL.Path, "realms", p.Realm, "protocol/openid-connect/token")

	p.TokenURL = parsedURL.String()

	return nil
}

func (p *KeyCloak) setAuthURL() error {
	if p.AuthURL != "" {
		return nil
	}

	if p.BaseURL == "" || p.Realm == "" {
		return fmt.Errorf("base_url and realm are required")
	}

	parsedURL, err := url.Parse(p.BaseURL)
	if err != nil {
		return fmt.Errorf("base_url is invalid: %s", err)
	}

	parsedURL.Path = path.Join(parsedURL.Path, "realms", p.Realm, "protocol/openid-connect/auth")

	p.AuthURL = parsedURL.String()

	return nil
}

func (p *KeyCloak) setCertURL() error {
	if p.CertURL != "" {
		return nil
	}

	if p.BaseURL == "" || p.Realm == "" {
		return fmt.Errorf("base_url and realm are required")
	}

	parsedURL, err := url.Parse(p.BaseURL)
	if err != nil {
		return fmt.Errorf("base_url is invalid: %s", err)
	}

	parsedURL.Path = path.Join(parsedURL.Path, "realms", p.Realm, "protocol/openid-connect/certs")

	p.CertURL = parsedURL.String()

	return nil
}
