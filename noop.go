package auth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/worldline-go/auth/models"
	"golang.org/x/oauth2/clientcredentials"
)

const NoopKey = "noop"

type Noop struct{}

func (Noop) GetLogoutURL() string {
	return NoopKey
}

func (Noop) GetLogoutURLExternal() string {
	return NoopKey
}

func (Noop) GetIntrospectURL() string {
	return NoopKey
}

func (Noop) GetScopes() []string {
	return nil
}

func (Noop) ClientConfig() (*clientcredentials.Config, error) {
	return nil, nil
}

func (Noop) GetCertURL() string {
	return NoopKey
}

func (Noop) GetTokenURL() string {
	return NoopKey
}

func (Noop) GetTokenURLExternal() string {
	return NoopKey
}

func (Noop) GetAuthURL() string {
	return NoopKey
}

func (Noop) GetAuthURLExternal() string {
	return NoopKey
}

func (Noop) GetClientID() string {
	return NoopKey
}

func (Noop) GetClientIDExternal() string {
	return NoopKey
}

func (Noop) GetClientSecret() string {
	return NoopKey
}

func (Noop) GetClientSecretExternal() string {
	return NoopKey
}

func (Noop) JWTKeyFunc(opts ...OptionJWK) (models.InfKeyFuncParser, error) {
	return NoopJWTKey{}, nil
}

func (Noop) IsNoop() bool {
	return true
}

func (Noop) RoundTripper(_ context.Context, transport http.RoundTripper) (http.RoundTripper, error) {
	return transport, nil
}

func (Noop) RoundTripperWrapper(_ *clientcredentials.Config) func(_ context.Context, transport http.RoundTripper) http.RoundTripper {
	return func(_ context.Context, transport http.RoundTripper) http.RoundTripper {
		return transport
	}
}

func (Noop) NewOauth2Shared(_ context.Context) (*OAuth2Shared, error) {
	return &OAuth2Shared{}, nil
}

type NoopJWTKey struct{}

func (NoopJWTKey) Keyfunc(_ *jwt.Token) (interface{}, error) {
	return NoopKey, nil
}

func (NoopJWTKey) EndBackground() {}

func (n NoopJWTKey) ParseWithClaims(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, claims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the JWT: %w", err)
	}

	return token, nil
}
