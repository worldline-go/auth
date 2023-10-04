package jwt

import "github.com/golang-jwt/jwt/v5"

type option struct {
	method  jwt.SigningMethod
	expFunc func() int64
	kid     string
}

type Option func(options *option)

// WithMethod sets the signing method for the JWT.
func WithMethod(method jwt.SigningMethod) Option {
	return func(options *option) {
		options.method = method
	}
}

// WithExpFunc sets the expiration function for the JWT.
func WithExpFunc(fn func() int64) Option {
	return func(options *option) {
		options.expFunc = fn
	}
}

// WithKID sets the key ID for the JWT.
func WithKID(kid string) Option {
	return func(options *option) {
		options.kid = kid
	}
}
