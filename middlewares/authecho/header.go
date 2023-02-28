package authecho

import (
	"github.com/labstack/echo/v4"
	"github.com/worldline-go/auth/claims"
)

type ClaimsHeader struct {
	// Scopes is the header name for scopes, default is X-Auth-Scopes.
	Scopes string `cfg:"scopes"`
	// Roles is the header name for roles, default is X-Auth-Roles.
	Roles string `cfg:"roles"`
	// User is the header name for user, default is X-Auth-User.
	User string `cfg:"user"`
	// Custom is the header name for custom claims.
	Custom map[string]string `cfg:"custom"`
}

func (h ClaimsHeader) SetHeaders(c echo.Context) {
	if h.Scopes == "" {
		h.Scopes = "X-Auth-Scopes"
	}
	if h.Roles == "" {
		h.Roles = "X-Auth-Roles"
	}
	if h.User == "" {
		h.User = "X-Auth-User"
	}

	claims, ok := c.Get("claims").(*claims.Custom)
	if !ok {
		return
	}

	c.Request().Header.Set(h.Scopes, claims.ScopeStr)
	c.Request().Header.Set(h.Roles, claims.RoleStr)
	c.Request().Header.Set(h.User, claims.Subject)

	for k, v := range h.Custom {
		claim, ok := claims.MapClaims[v].(string)
		if !ok {
			c.Logger().Debug("claim not found or not a string: ", v)
			continue
		}

		c.Request().Header.Set(k, claim)
	}
}
