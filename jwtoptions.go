package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
)

type optionJWT struct {
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

type OptionJWT func(options *optionJWT)

func WithSecretByte(secret []byte) OptionJWT {
	return func(options *optionJWT) {
		options.secretByte = secret
	}
}

func WithRSAPrivateKey(secret *rsa.PrivateKey) OptionJWT {
	return func(options *optionJWT) {
		options.secretRSAPrivate = secret
	}
}

func WithRSAPublicKey(secret *rsa.PublicKey) OptionJWT {
	return func(options *optionJWT) {
		options.secretRSAPublic = secret
	}
}

func WithECDSAPrivateKey(secret *ecdsa.PrivateKey) OptionJWT {
	return func(options *optionJWT) {
		options.secretECDSAPrivate = secret
	}
}

func WithECDSAPublicKey(secret *ecdsa.PublicKey) OptionJWT {
	return func(options *optionJWT) {
		options.secretECDSAPublic = secret
	}
}

func WithED25519PrivateKey(secret ed25519.PrivateKey) OptionJWT {
	return func(options *optionJWT) {
		options.secretED25519Private = secret
	}
}

func WithED25519PublicKey(secret ed25519.PublicKey) OptionJWT {
	return func(options *optionJWT) {
		options.secretED25519Public = secret
	}
}

// WithMethod sets the signing method for the JWT.
func WithMethod(method jwt.SigningMethod) OptionJWT {
	return func(options *optionJWT) {
		options.method = method
	}
}

// WithExpFunc sets the expiration function for the JWT.
func WithExpFunc(fn func() int64) OptionJWT {
	return func(options *optionJWT) {
		options.expFunc = fn
	}
}

// WithKID sets the key ID for the JWT.
func WithKID(kid string) OptionJWT {
	return func(options *optionJWT) {
		options.kid = kid
	}
}
