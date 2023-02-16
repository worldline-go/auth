package authecho

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/worldline-go/auth/claims"
)

// MiddlewareScope that checks the scope claim.
// This middleware just work with *claims.Custom claims.
func MiddlewareScope(scopes ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			claims := c.Get("claims").(*claims.Custom)

			for _, scope := range scopes {
				if !claims.HasScope(scope) {
					return echo.NewHTTPError(http.StatusUnauthorized, "scope not authorized")
				}
			}

			return next(c)
		}
	}
}
