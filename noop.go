package auth

import (
	"context"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2/clientcredentials"
)

const NoopKey = "noop"

type Noop struct{}

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

func (Noop) JWTKeyFunc(opts ...OptionJWK) (InfJWTKeyFunc, error) {
	return NoopJWTKey{}, nil
}

func (Noop) IsNoop() bool {
	return true
}

func (Noop) RoundTripper(ctx context.Context, transport http.RoundTripper) (http.RoundTripper, error) {
	return transport, nil
}

func (Noop) RoundTripperWrapper(_ *clientcredentials.Config) func(_ context.Context, transport http.RoundTripper) http.RoundTripper {
	return func(_ context.Context, transport http.RoundTripper) http.RoundTripper {
		return transport
	}
}

type NoopJWTKey struct{}

func (NoopJWTKey) Keyfunc(token *jwt.Token) (interface{}, error) {
	return NoopKey, nil
}

func (NoopJWTKey) EndBackground() {}

func (NoopJWTKey) Parser(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
	return nil, nil
}
