package authecho

import (
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// NewSkipper returns a new Skipper that skips the given suffixes.
//
// Default suffixes are: [/ping, /health, /metrics].
func NewSkipper(suffixes ...string) middleware.Skipper {
	if suffixes == nil {
		// Skip ping, health and metrics endpoints for less noise.
		suffixes = []string{"/ping", "/health", "/metrics"}
	}

	return func(c echo.Context) bool {
		path := c.Request().URL.Path

		for _, p := range suffixes {
			if strings.HasSuffix(path, p) {
				return true
			}
		}

		return false
	}
}
