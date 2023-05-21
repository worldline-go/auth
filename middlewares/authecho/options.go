package authecho

import (
	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4/middleware"
)

type options struct {
	config    echojwt.Config
	newClaims func() jwt.Claims
	redirect  *RedirectSetting

	noop         bool
	claimsHeader *ClaimsHeader
	parser       func(tokenString string, claims jwt.Claims) (*jwt.Token, error)
}

type Option func(*options)

// WithConfig sets the config to use
//
// Don't use if you don't know what you are doing.
func WithConfig(cfg echojwt.Config) Option {
	return func(opts *options) {
		opts.config = cfg
	}
}

func WithNoop(noop bool) Option {
	return func(opts *options) {
		opts.noop = noop
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

func WithParserFunc(fn func(tokenString string, claims jwt.Claims) (*jwt.Token, error)) Option {
	return func(opts *options) {
		opts.parser = fn
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

func WithClaimsHeader(claimsHeader *ClaimsHeader) Option {
	return func(opts *options) {
		opts.claimsHeader = claimsHeader
	}
}
