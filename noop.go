package auth

import (
	"context"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2/clientcredentials"
)

type Noop struct{}

func (Noop) ClientConfig() (*clientcredentials.Config, error) {
	return nil, nil
}

func (Noop) GetCertURL() string {
	return "noop"
}

func (Noop) GetTokenURL() string {
	return "noop"
}

func (Noop) GetAuthURL() string {
	return "noop"
}

func (Noop) GetClientID() string {
	return "noop"
}

func (Noop) GetClientSecret() string {
	return "noop"
}

func (Noop) JWTKeyFunc(ctx context.Context, opts ...OptionJWK) (InfJWTKeyFunc, error) {
	return NoopJWTKey{}, nil
}

func (Noop) IsNoop() bool {
	return true
}

type NoopJWTKey struct{}

func (NoopJWTKey) Keyfunc(token *jwt.Token) (interface{}, error) {
	return nil, nil
}

func (NoopJWTKey) EndBackground() {}

func (NoopJWTKey) Parser(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
	return nil, nil
}
