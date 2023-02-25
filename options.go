package auth

import (
	"net/http"
	"time"
)

type optionsParser struct {
	jwt bool
}

type OptionParser func(options *optionsParser)

func WithJwt() OptionParser {
	return func(options *optionsParser) {
		options.jwt = true
	}
}

type optionsJWK struct {
	refreshErrorHandler func(err error)
	refreshInterval     time.Duration
	refreshUnknownKID   bool
	client              *http.Client
}

type OptionJWK func(options *optionsJWK)

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

func WithRefreshUnknownKID(v bool) OptionJWK {
	return func(options *optionsJWK) {
		options.refreshUnknownKID = v
	}
}

func WithClient(client *http.Client) OptionJWK {
	return func(options *optionsJWK) {
		options.client = client
	}
}
