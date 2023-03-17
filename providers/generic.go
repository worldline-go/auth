package providers

import (
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type Generic struct {
	// Extra settings for clients.
	// ClientID is the application's ID.
	ClientID string `cfg:"client_id"`

	// ClientSecret is the application's secret.
	ClientSecret string `cfg:"client_secret" log:"false"`

	// Scope specifies optional requested permissions.
	Scopes []string `cfg:"scopes"`

	// End of extra settings for clients.

	// CertURL is the resource server's public key URL.
	//
	// BaseURL and REALM are used to construct the CertURL.
	CertURL string `cfg:"cert_url"`

	// IntrospectURL is the check the active or not with request.
	//
	// If set, certURL will be ignored.
	IntrospectURL string `cfg:"introspect_url"`

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
}

func (p *Generic) GetIntrospectURL() string {
	return p.IntrospectURL
}

func (p *Generic) GetScopes() []string {
	return p.Scopes
}

func (p *Generic) GetCertURL() string {
	return p.CertURL
}

func (p *Generic) GetAuthURL() string {
	return p.AuthURL
}

func (p *Generic) GetTokenURL() string {
	return p.TokenURL
}

func (p *Generic) GetClientID() string {
	return p.ClientID
}

func (p *Generic) GetClientSecret() string {
	return p.ClientSecret
}

func (p *Generic) ClientConfig() (*clientcredentials.Config, error) {
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
