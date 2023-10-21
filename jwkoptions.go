package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/rs/zerolog/log"
	"github.com/worldline-go/auth/models"
)

func GetOptionJWK(opts ...OptionJWK) optionsJWK {
	option := optionsJWK{
		RefreshErrorHandler: func(err error) {
			log.Warn().Err(err).Msg("failed to refresh jwt.Keyfunc")
		},
		RefreshInterval: time.Minute * 5,
		Ctx:             context.Background(),
	}

	for _, opt := range opts {
		opt(&option)
	}

	return option
}

func MapOptionKeyfunc(opt optionsJWK) keyfunc.Options {
	return keyfunc.Options{
		Ctx:                 opt.Ctx,
		RefreshErrorHandler: opt.RefreshErrorHandler,
		// RefreshRateLimit:    time.Minute * 5,
		RefreshInterval: opt.RefreshInterval,
		Client:          opt.Client,
	}
}

type optionsJWK struct {
	Client              *http.Client
	RefreshErrorHandler func(err error)
	RefreshInterval     time.Duration
	Ctx                 context.Context
	Introspect          bool
	KeyFunc             models.InfKeyFunc
}

type OptionJWK func(options *optionsJWK)

// WithGivenKeys is used to set the given keys used to verify the token.
//
// Return ErrKIDNotFound if the kid is not found.
//
// Example:
//
//	// Create the JWKS from the given keys.
//	givenKeys := map[string]keyfunc.GivenKey{
//		"my-key-id": keyfunc.NewGivenHMAC(...),
//	}
//	jwks := keyfunc.NewGiven(givenKeys)
func WithKeyFunc(keyFunc models.InfKeyFunc) OptionJWK {
	return func(options *optionsJWK) {
		options.KeyFunc = keyFunc
	}
}

func WithIntrospect(v bool) OptionJWK {
	return func(options *optionsJWK) {
		options.Introspect = v
	}
}

// WithRefreshErrorHandler sets the refresh error handler for the jwt.Key.
func WithRefreshErrorHandler(fn func(err error)) OptionJWK {
	return func(options *optionsJWK) {
		options.RefreshErrorHandler = fn
	}
}

// WithRefreshInterval sets the refresh interval for the jwt.Keyfunc default is 5 minutes.
func WithRefreshInterval(d time.Duration) OptionJWK {
	return func(options *optionsJWK) {
		options.RefreshInterval = d
	}
}

// WithClient is used to set the http.Client used to fetch the JWKs.
func WithClient(client *http.Client) OptionJWK {
	return func(options *optionsJWK) {
		options.Client = client
	}
}

// WithContext is used to set the context used to fetch the JWKs.
func WithContext(ctx context.Context) OptionJWK {
	return func(options *optionsJWK) {
		options.Ctx = ctx
	}
}
