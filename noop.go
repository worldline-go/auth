package auth

import (
	"context"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2/clientcredentials"
)

const noopKey = "noop"

type Noop struct{}

func (Noop) ClientConfig() (*clientcredentials.Config, error) {
	return nil, nil
}

func (Noop) GetCertURL() string {
	return noopKey
}

func (Noop) GetTokenURL() string {
	return noopKey
}

func (Noop) GetAuthURL() string {
	return noopKey
}

func (Noop) GetClientID() string {
	return noopKey
}

func (Noop) GetClientSecret() string {
	return noopKey
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
	return noopKey, nil
}

func (NoopJWTKey) EndBackground() {}

func (NoopJWTKey) Parser(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
	return nil, nil
}
