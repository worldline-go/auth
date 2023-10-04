package authecho

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

var DisableRoleCheckKey = "auth_disable_role_check"

type ClaimsRole interface {
	HasRole(role string) bool
}

// MiddlewareRole that checks the role claim.
// This middleware just work with ClaimsRole interface in claim.
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
			if options.noop {
				return next(c)
			}

			if v, ok := c.Get(DisableRoleCheckKey).(bool); ok && v {
				return next(c)
			}

			if v, ok := c.Get(authNoopKey).(bool); ok && v {
				return next(c)
			}

			if len(methodSet) > 0 {
				if _, ok := methodSet[c.Request().Method]; !ok {
					return next(c)
				}
			}

			claimsV, ok := c.Get("claims").(ClaimsRole)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "claims not found")
			}

			if len(options.roles) > 0 {
				found := false
				for _, role := range options.roles {
					if claimsV.HasRole(role) {
						found = true

						break
					}
				}

				if !found {
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
	noop    bool
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

// WithNoopRole sets the noop option.
//
// If provider already has a noop, this one will be ignored.
func WithNoopRole(v bool) OptionRole {
	return func(opts *optionsRole) {
		opts.noop = v
	}
}
