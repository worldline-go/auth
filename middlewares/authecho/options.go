package authecho

import (
	"github.com/golang-jwt/jwt/v4"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4/middleware"
)

type options struct {
	config    echojwt.Config
	newClaims func() jwt.Claims
	redirect  *RedirectSetting
}

type Option func(*options)

func WithConfig(cfg echojwt.Config) Option {
	return func(opts *options) {
		opts.config = cfg
	}
}

// WithClaims sets the claims to use, function must return a pointer.
func WithClaims(newClaims func() jwt.Claims) Option {
	return func(opts *options) {
		// check claims is pointer
		opts.newClaims = newClaims
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

func WithRedirect(redirect *RedirectSetting) Option {
	return func(opts *options) {
		opts.redirect = redirect
	}
}
