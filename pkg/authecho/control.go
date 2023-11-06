package authecho

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
)

var DisableControlCheckKey = "auth_disable_control_check"

// MiddlewareControl that checks the claim manually with a function.
func MiddlewareControl[T any](fn func(c echo.Context, claim T) error, opts ...OptionControl) echo.MiddlewareFunc {
	var options optionsControl
	for _, opt := range opts {
		opt(&options)
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if options.noop {
				return next(c)
			}

			if v, ok := c.Get(DisableControlCheckKey).(bool); ok && v {
				return next(c)
			}

			if v, ok := c.Get(KeyAuthNoop).(bool); ok && v {
				return next(c)
			}

			claimsV, ok := c.Get(KeyClaims).(T)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "claims not found")
			}

			if err := fn(c, claimsV); err != nil {
				return err
			}
			fmt.Println("MiddlewareControl-2")

			return next(c)
		}
	}
}

type optionsControl struct {
	noop bool
}

type OptionControl func(*optionsControl)

// WithNoopControl sets the noop option.
//
// If provider already has a noop, this one will be ignored.
func WithNoopControl(v bool) OptionControl {
	return func(opts *optionsControl) {
		opts.noop = v
	}
}
