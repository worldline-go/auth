package authecho

import (
	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/worldline-go/auth/claims"

	echojwt "github.com/labstack/echo-jwt/v4"
)

// MiddlewareJWT returns a JWT middleware.
// Default claims is *claims.Custom.
func MiddlewareJWT(opts ...Option) echo.MiddlewareFunc {
	var options options
	for _, opt := range opts {
		opt(&options)
	}

	if options.config.NewClaimsFunc == nil {
		options.config.NewClaimsFunc = func(c echo.Context) jwt.Claims {
			var value jwt.Claims

			if options.newClaims == nil {
				value = &claims.Custom{}
			} else {
				value = options.newClaims()
			}

			c.Set("claims", value)

			return value
		}
	}

	return echojwt.WithConfig(options.config)
}
