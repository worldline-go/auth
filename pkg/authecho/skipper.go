package authecho

import (
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// NewSkipper returns a new Skipper that skips the given suffixes.
//
// Set skip is true to skip all.
//
// Default suffixes are: [/ping, /health, /metrics].
func NewSkipper(opts ...OptionSkipper) middleware.Skipper {
	o := optionsSkipper{
		skipAll:  false,
		suffixes: []string{"/ping", "/health", "/metrics"},
	}

	for _, opt := range opts {
		opt(&o)
	}

	return func(c echo.Context) bool {
		if o.skipAll {
			return true
		}

		path := c.Request().URL.Path

		for _, p := range o.suffixes {
			if strings.HasSuffix(path, p) {
				return true
			}
		}

		return false
	}
}

type optionsSkipper struct {
	suffixes []string
	skipAll  bool
}

type OptionSkipper func(*optionsSkipper)

// WithSuffixes sets the suffixes to skip.
func WithSuffixes(suffixes ...string) OptionSkipper {
	return func(opts *optionsSkipper) {
		opts.suffixes = suffixes
	}
}

// WithSkipAll sets skipAll to true and disable the check token.
func WithSkipAll(v bool) OptionSkipper {
	return func(opts *optionsSkipper) {
		opts.skipAll = v
	}
}
