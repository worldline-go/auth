package authecho

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

var DisableScopeCheckKey = "auth_disable_scope_check"

type ClaimsScope interface {
	HasScope(scope string) bool
}

// MiddlewareScope that checks the scope claim.
//
// This middleware just work with ClaimsScope interface in claims.
func MiddlewareScope(opts ...OptionScope) echo.MiddlewareFunc {
	var options optionsScope
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

			if v, ok := c.Get(DisableScopeCheckKey).(bool); ok && v {
				return next(c)
			}

			if v, ok := c.Get(KeyAuthNoop).(bool); ok && v {
				return next(c)
			}

			if len(methodSet) > 0 {
				if _, ok := methodSet[c.Request().Method]; !ok {
					return next(c)
				}
			}

			claimsV, ok := c.Get(KeyClaims).(ClaimsScope)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "claims not found")
			}

			if len(options.scopes) > 0 {
				found := false
				for _, scope := range options.scopes {
					if claimsV.HasScope(scope) {
						found = true

						break
					}
				}

				if !found {
					return echo.NewHTTPError(http.StatusUnauthorized, "scope not authorized")
				}
			}

			return next(c)
		}
	}
}

type optionsScope struct {
	scopes  []string
	methods []string
	noop    bool
}

type OptionScope func(*optionsScope)

// WithRoles sets the roles to check.
func WithScopes(scopes ...string) OptionScope {
	return func(opts *optionsScope) {
		opts.scopes = scopes
	}
}

// WithMethods sets the methods to check.
func WithMethodsScope(methods ...string) OptionScope {
	return func(opts *optionsScope) {
		opts.methods = methods
	}
}

// WithNoopScope sets the noop option.
//
// If provider already has a noop, this one will be ignored.
func WithNoopScope(v bool) OptionScope {
	return func(opts *optionsScope) {
		opts.noop = v
	}
}
