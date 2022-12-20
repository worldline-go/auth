package authecho

import (
	"github.com/golang-jwt/jwt/v4"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4/middleware"
)

type options struct {
	config echojwt.Config
	claims jwt.Claims
}

type Option func(*options)

func WithConfig(cfg echojwt.Config) Option {
	return func(opts *options) {
		opts.config = cfg
	}
}

// WithClaims sets the claims to use, claims must be a pointer.
func WithClaims(claims jwt.Claims) Option {
	return func(opts *options) {
		opts.claims = claims
	}
}

func WithKeyFunc(fn jwt.Keyfunc) Option {
	return func(opts *options) {
		opts.config.KeyFunc = fn
	}
}

func WithSkipper(skipper middleware.Skipper) Option {
	return func(opts *options) {
		opts.config.Skipper = skipper
	}
}
