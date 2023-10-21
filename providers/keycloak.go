package providers

import (
	"fmt"
	"net/url"
	"path"

	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type KeyCloak struct {
	// Extra settings for clients.

	// ClientID is the application's ID.
	ClientID string `cfg:"client_id"`

	// ClientIDExternal for reaching the client id from outside.
	ClientIDExternal string `cfg:"client_id_external"`

	// ClientSecret is the application's secret.
	ClientSecret string `cfg:"client_secret" log:"false"`

	// ClientSecretExternal for reaching the client secret from outside.
	ClientSecretExternal string `cfg:"client_secret_external"`

	// Scope specifies optional requested permissions.
	Scopes []string `cfg:"scopes"`

	// End of extra settings for clients.

	// CertURL is the resource server's public key URL.
	//
	// BaseURL and REALM are used to construct the CertURL.
	CertURL string `cfg:"cert_url"`

	// IntrospectURL is the check the active or not with request.
	IntrospectURL string `cfg:"introspect_url"`

	// AuthURL is the resource server's authorization endpoint
	// use for redirection to login page.
	//
	// BaseURL and REALM are used to construct the AuthURL.
	AuthURL string `cfg:"auth_url"`

	// AuthURLExternal for reaching the auth page from outside.
	//
	// Default is AuthURL.
	AuthURLExternal string `cfg:"auth_url_external"`

	// TokenURL is the resource server's token endpoint
	// URL. This is a constant specific to each server.
	//
	// BaseURL and REALM are used to construct the TokenURL.
	TokenURL string `cfg:"token_url"`

	// TokenURLExternal for reaching the token page from outside.
	//
	// Default is TokenURL.
	TokenURLExternal string `cfg:"token_url_external"`

	// BaseURL is the resource server's base URL like https://keycloak:8080.
	//
	// If your server has auth path set like https://keycloak:8080/auth/
	BaseURL string `cfg:"base_url"`

	// BaseURLExternal for reaching the base url from outside.
	//
	// Default is BaseURL.
	BaseURLExternal string `cfg:"base_url_external"`

	LogoutURL string `cfg:"logout_url"`
	// LogoutURLExternal for reaching the logout url from outside.
	// Default is LogoutURL.
	LogoutURLExternal string `cfg:"logout_url_external"`
	// Realm is the resource server's realm like master.
	Realm string `cfg:"realm"`
}

func (p *KeyCloak) GetLogoutURL() string {
	if p.LogoutURL != "" {
		return p.LogoutURL
	}

	logoutURL, err := p.getLogoutURL(p.BaseURL, p.Realm)
	if err != nil {
		log.Error().Err(err).Msg("failed to get LogoutURL")
		return ""
	}

	p.LogoutURL = logoutURL
	return p.LogoutURL
}

func (p *KeyCloak) GetLogoutURLExternal() string {
	if p.LogoutURLExternal != "" {
		return p.LogoutURLExternal
	}

	baseURL := p.BaseURLExternal
	if baseURL == "" {
		baseURL = p.BaseURL
	}

	logoutURL, err := p.getLogoutURL(baseURL, p.Realm)
	if err != nil {
		log.Error().Err(err).Msg("failed to get LogoutURL external")
		return ""
	}

	p.LogoutURLExternal = logoutURL
	return p.LogoutURLExternal
}

func (p *KeyCloak) GetIntrospectURL() string {
	return p.IntrospectURL
}

func (p *KeyCloak) GetScopes() []string {
	return p.Scopes
}

func (p *KeyCloak) GetCertURL() string {
	_ = p.setCertURL()

	return p.CertURL
}

func (p *KeyCloak) GetAuthURL() string {
	if p.AuthURL != "" {
		return p.AuthURL
	}

	authURL, err := p.getAuthURL(p.BaseURL, p.Realm)
	if err != nil {
		log.Error().Err(err).Msg("failed to get AuthURL")
		return ""
	}

	p.AuthURL = authURL
	return p.AuthURL
}

func (p *KeyCloak) GetAuthURLExternal() string {
	if p.AuthURLExternal != "" {
		return p.AuthURLExternal
	}

	baseURL := p.BaseURLExternal
	if baseURL == "" {
		baseURL = p.BaseURL
	}

	authURL, err := p.getAuthURL(baseURL, p.Realm)
	if err != nil {
		log.Error().Err(err).Msg("failed to get AuthURL external")
		return ""
	}

	p.AuthURLExternal = authURL
	return p.AuthURLExternal
}

func (p *KeyCloak) GetTokenURL() string {
	if p.TokenURL != "" {
		return p.TokenURL
	}

	tokenURL, err := p.getTokenURL(p.BaseURL, p.Realm)
	if err != nil {
		log.Error().Err(err).Msg("failed to get TokenURL")
		return ""
	}

	p.TokenURL = tokenURL
	return p.TokenURL
}

func (p *KeyCloak) GetTokenURLExternal() string {
	if p.TokenURLExternal != "" {
		return p.TokenURLExternal
	}

	baseURL := p.BaseURLExternal
	if baseURL == "" {
		baseURL = p.BaseURL
	}

	tokenURL, err := p.getTokenURL(baseURL, p.Realm)
	if err != nil {
		log.Error().Err(err).Msg("failed to get TokenURL external")
		return ""
	}

	p.TokenURLExternal = tokenURL
	return p.TokenURLExternal
}

func (p *KeyCloak) GetClientID() string {
	return p.ClientID
}

func (p *KeyCloak) GetClientIDExternal() string {
	return p.ClientIDExternal
}

func (p *KeyCloak) GetClientSecret() string {
	return p.ClientSecret
}

func (p *KeyCloak) GetClientSecretExternal() string {
	return p.ClientSecretExternal
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

func (p *KeyCloak) getLogoutURL(baseURL, realm string) (string, error) {
	if baseURL == "" || realm == "" {
		return "", fmt.Errorf("base_url and realm are required")
	}

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("base_url is invalid: %s", err)
	}

	parsedURL.Path = path.Join(parsedURL.Path, "realms", realm, "protocol/openid-connect/logout")

	return parsedURL.String(), nil
}

func (p *KeyCloak) getTokenURL(baseURL, realm string) (string, error) {
	if baseURL == "" || realm == "" {
		return "", fmt.Errorf("base_url and realm are required")
	}

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("base_url is invalid: %s", err)
	}

	parsedURL.Path = path.Join(parsedURL.Path, "realms", realm, "protocol/openid-connect/token")

	return parsedURL.String(), nil
}

func (p *KeyCloak) getAuthURL(baseURL, realm string) (string, error) {
	if baseURL == "" || realm == "" {
		return "", fmt.Errorf("base_url and realm are required")
	}

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("base_url is invalid: %s", err)
	}

	parsedURL.Path = path.Join(parsedURL.Path, "realms", realm, "protocol/openid-connect/auth")

	return parsedURL.String(), nil
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
