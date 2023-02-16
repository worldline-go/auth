package authecho

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/worldline-go/auth/claims"
)

// MiddlewareRole that checks the role claim.
// This middleware just work with *claims.Custom claims.
func MiddlewareRole(roles ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			claims := c.Get("claims").(*claims.Custom)

			for _, role := range roles {
				if !claims.HasRole(role) {
					return echo.NewHTTPError(http.StatusUnauthorized, "role not authorized")
				}
			}

			return next(c)
		}
	}
}
