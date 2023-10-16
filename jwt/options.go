package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
)

type option struct {
	method  jwt.SigningMethod
	expFunc func() int64
	kid     string

	secretByte []byte

	secretRSAPrivate *rsa.PrivateKey
	secretRSAPublic  *rsa.PublicKey

	secretECDSAPrivate *ecdsa.PrivateKey
	secretECDSAPublic  *ecdsa.PublicKey

	secretED25519Private ed25519.PrivateKey
	secretED25519Public  ed25519.PublicKey
}

type Option func(options *option)

func WithSecretByte(secret []byte) Option {
	return func(options *option) {
		options.secretByte = secret
	}
}

func WithRSAPrivateKey(secret *rsa.PrivateKey) Option {
	return func(options *option) {
		options.secretRSAPrivate = secret
	}
}

func WithRSAPublicKey(secret *rsa.PublicKey) Option {
	return func(options *option) {
		options.secretRSAPublic = secret
	}
}

func WithECDSAPrivateKey(secret *ecdsa.PrivateKey) Option {
	return func(options *option) {
		options.secretECDSAPrivate = secret
	}
}

func WithECDSAPublicKey(secret *ecdsa.PublicKey) Option {
	return func(options *option) {
		options.secretECDSAPublic = secret
	}
}

func WithED25519PrivateKey(secret ed25519.PrivateKey) Option {
	return func(options *option) {
		options.secretED25519Private = secret
	}
}

func WithED25519PublicKey(secret ed25519.PublicKey) Option {
	return func(options *option) {
		options.secretED25519Public = secret
	}
}

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
