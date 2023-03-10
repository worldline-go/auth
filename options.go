package auth

import (
	"net/http"
	"time"
)

type optionsActiveProvider struct {
	noop bool
}

type OptionActiveProvider func(options *optionsActiveProvider)

// WithNoop sets the active provider to noop.
func WithNoop(v bool) OptionActiveProvider {
	return func(options *optionsActiveProvider) {
		options.noop = v
	}
}

type optionsJWK struct {
	client              *http.Client
	refreshErrorHandler func(err error)
	refreshInterval     time.Duration
	refreshUnknownKID   bool
}

type OptionJWK func(options *optionsJWK)

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
