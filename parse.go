package auth

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

var ErrTokenInvalid = fmt.Errorf("token is invalid")

// Parser returns a function to parse a token and a function to stop the background refresh certs.
func (p *Provider) Parser(ctx context.Context, opts ...OptionParser) (func(string, jwt.Claims) (*jwt.Token, error), func(), error) {
	options := optionsParser{
		jwt: true,
	}

	for _, opt := range opts {
		opt(&options)
	}

	if options.jwt {
		jwks, err := p.GetJwks(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get jwks: %w", err)
		}

		return func(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
			// Parse the JWT.
			token, err := jwt.ParseWithClaims(tokenString, claims, jwks.Keyfunc)
			if err != nil {
				return nil, fmt.Errorf("failed to parse the JWT: %w", err)
			}

			// Check if the token is valid.
			if !token.Valid {
				return nil, ErrTokenInvalid
			}

			return token, nil
		}, jwks.EndBackground, nil
	}

	return nil, nil, fmt.Errorf("no parser configured")
}
