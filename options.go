package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/MicahParks/keyfunc/v2"
)

type optionsActiveProvider struct {
	noop   bool
	active string
}

type OptionActiveProvider func(options *optionsActiveProvider)

// WithNoop sets the active provider to noop.
func WithNoop(v bool) OptionActiveProvider {
	return func(options *optionsActiveProvider) {
		options.noop = v
	}
}

func WithActive(provider string) OptionActiveProvider {
	return func(options *optionsActiveProvider) {
		options.active = provider
	}
}

type optionsJWK struct {
	client              *http.Client
	refreshErrorHandler func(err error)
	refreshInterval     time.Duration
	refreshUnknownKID   bool
	ctx                 context.Context
	introspect          bool
	givenKeys           map[string]keyfunc.GivenKey
	givenKIDOverride    bool
}

type OptionJWK func(options *optionsJWK)

func WithIntrospect(v bool) OptionJWK {
	return func(options *optionsJWK) {
		options.introspect = v
	}
}

// WithRefreshErrorHandler sets the refresh error handler for the jwt.Key.
func WithRefreshErrorHandler(fn func(err error)) OptionJWK {
	return func(options *optionsJWK) {
		options.refreshErrorHandler = fn
	}
}

// WithRefreshInterval sets the refresh interval for the jwt.Keyfunc default is 5 minutes.
func WithRefreshInterval(d time.Duration) OptionJWK {
	return func(options *optionsJWK) {
		options.refreshInterval = d
	}
}

// WithRefreshUnknownKID sets the refresh unknown KID for the jwt.Key, default is false.
func WithRefreshUnknownKID(v bool) OptionJWK {
	return func(options *optionsJWK) {
		options.refreshUnknownKID = v
	}
}

// WithClient is used to set the http.Client used to fetch the JWKs.
func WithClient(client *http.Client) OptionJWK {
	return func(options *optionsJWK) {
		options.client = client
	}
}

// WithContext is used to set the context used to fetch the JWKs.
func WithContext(ctx context.Context) OptionJWK {
	return func(options *optionsJWK) {
		options.ctx = ctx
	}
}

func WithGivenKeys(keys map[string]keyfunc.GivenKey) OptionJWK {
	return func(options *optionsJWK) {
		options.givenKeys = keys
	}
}

func WithGivenKIDOverride(v bool) OptionJWK {
	return func(options *optionsJWK) {
		options.givenKIDOverride = v
	}
}
