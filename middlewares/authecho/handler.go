package authecho

import (
	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/worldline-go/auth/claims"

	echojwt "github.com/labstack/echo-jwt/v4"
)

// MiddlewareJWT returns a JWT middleware.
func MiddlewareJWT(opts ...Option) echo.MiddlewareFunc {
	var options options
	for _, opt := range opts {
		opt(&options)
	}

	if options.config.NewClaimsFunc == nil {
		options.config.NewClaimsFunc = func(c echo.Context) jwt.Claims {
			value := options.claims
			if value == nil {
				value = &claims.Custom{}
			}

			c.Set("claims", value)

			return value
		}
	}

	return echojwt.WithConfig(options.config)
}
