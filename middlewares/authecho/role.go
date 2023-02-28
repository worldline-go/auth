package authecho

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/worldline-go/auth/claims"
)

// MiddlewareRole that checks the role claim.
// This middleware just work with *claims.Custom claims.
func MiddlewareRole(opts ...OptionRole) echo.MiddlewareFunc {
	var options optionsRole
	for _, opt := range opts {
		opt(&options)
	}

	methodSet := make(map[string]struct{}, len(options.methods))
	for _, method := range options.methods {
		methodSet[strings.ToUpper(method)] = struct{}{}
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if len(methodSet) > 0 {
				if _, ok := methodSet[c.Request().Method]; !ok {
					return next(c)
				}
			}

			claims, ok := c.Get("claims").(*claims.Custom)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "claims not found")
			}

			for _, role := range options.roles {
				if !claims.HasRole(role) {
					return echo.NewHTTPError(http.StatusUnauthorized, "role not authorized")
				}
			}

			return next(c)
		}
	}
}

type optionsRole struct {
	roles   []string
	methods []string
}

type OptionRole func(*optionsRole)

// WithRoles sets the roles to check.
func WithRoles(roles ...string) OptionRole {
	return func(opts *optionsRole) {
		opts.roles = roles
	}
}

// WithMethods sets the methods to check.
func WithMethodsRole(methods ...string) OptionRole {
	return func(opts *optionsRole) {
		opts.methods = methods
	}
}
