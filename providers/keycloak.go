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

	// AuthURL is the resource server's authorization endpoint
	// use for redirection to login page.
	//
	// BaseURL and REALM are used to construct the token URL.
	AuthURL string `cfg:"auth_url"`

	// TokenURL is the resource server's token endpoint
	// URL. This is a constant specific to each server.
	//
	// BaseURL and REALM are used to construct the token URL.
	TokenURL string `cfg:"token_url"`

	// BaseURL is the resource server's base URL like https://keycloak:8080.
	BaseURL string `cfg:"base_url"`
	// Realm is the resource server's realm like master.
	Realm string `cfg:"realm"`
}

func (p *KeyCloak) GetAuthURL() (string, error) {
	if err := p.SetAuthURL(); err != nil {
		return "", err
	}

	return p.AuthURL, nil
}

func (p *KeyCloak) GetTokenURL() (string, error) {
	if err := p.SetTokenURL(); err != nil {
		return "", err
	}

	return p.TokenURL, nil
}

func (p *KeyCloak) GetClientID() string {
	return p.ClientID
}

func (p *KeyCloak) GetClientSecret() string {
	return p.ClientSecret
}

func (p *KeyCloak) SetTokenURL() error {
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

func (p *KeyCloak) SetAuthURL() error {
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

func (p *KeyCloak) Config() (*clientcredentials.Config, error) {
	if err := p.SetTokenURL(); err != nil {
		return nil, err
	}

	if err := p.SetAuthURL(); err != nil {
		return nil, err
	}

	return &clientcredentials.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		TokenURL:     p.TokenURL,
		Scopes:       p.Scopes,
		AuthStyle:    oauth2.AuthStyleInHeader,
	}, nil
}

// PublicKeyURL returns the resource server's public key URL.
func (p *KeyCloak) CertURL() (string, error) {
	if p.BaseURL == "" || p.Realm == "" {
		return "", fmt.Errorf("base_url and realm are required")
	}

	parsedURL, err := url.Parse(p.BaseURL)
	if err != nil {
		return "", fmt.Errorf("base_url is invalid: %s", err)
	}

	parsedURL.Path = path.Join(parsedURL.Path, "realms", p.Realm, "protocol/openid-connect/certs")

	return parsedURL.String(), nil
}
