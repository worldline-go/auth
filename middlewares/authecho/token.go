package authecho

import (
	"strings"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
	"github.com/worldline-go/auth/request"
	"github.com/worldline-go/auth/store"
)

// RefreshToken refreshes the access token and set the cookie.
func RefreshToken(c echo.Context, refreshToken, cookieName string, oldCookieValue string, redirect *RedirectSetting, sessionStore *sessions.FilesystemStore) (*store.Token, error) {
	body, err := request.DefaultAuth.RefreshToken(c.Request().Context(), request.RefreshTokenConfig{
		RefreshToken: refreshToken,
		AuthRequestConfig: request.AuthRequestConfig{
			ClientID:     redirect.ClientID,
			ClientSecret: redirect.ClientSecret,
			TokenURL:     redirect.TokenURL,
		},
	})
	if err != nil {
		return nil, err
	}

	// parse body to cookie
	cookieParsed, err := store.Parse(string(body))
	if err != nil {
		return nil, err
	}

	if redirect.UseSession {
		if _, err := store.SetSessionB64(c.Request(), c.Response(), body, cookieName, "cookie", sessionStore); err != nil {
			c.Logger().Debug("error save session", err)
		}

		return cookieParsed, nil
	}

	// set the cookie
	cookieValue := store.SetCookieB64(c.Response(), body, cookieName, redirect.MapConfigCookie())

	// switch the cookie value in request header
	cookieHeaderValue := c.Request().Header.Get("Cookie")
	if cookieHeaderValue != "" {
		cookieHeaderValue = strings.Replace(cookieHeaderValue, oldCookieValue, cookieValue, 1)
		c.Request().Header.Set("Cookie", cookieHeaderValue)
	}

	return cookieParsed, nil
}

func CodeToken(c echo.Context, code, cookieName string, redirect *RedirectSetting, sessionStore *sessions.FilesystemStore) error {
	redirectURI, err := RedirectURI(c.Request().Clone(c.Request().Context()), redirect.Callback, redirect.BaseURL, redirect.Schema)
	if err != nil {
		c.Set("auth_error", err.Error())
		return err
	}

	body, err := request.DefaultAuth.AuthorizationCode(c.Request().Context(), request.AuthorizationCodeConfig{
		Code:        code,
		RedirectURI: redirectURI,
		AuthRequestConfig: request.AuthRequestConfig{
			ClientID:     redirect.ClientID,
			ClientSecret: redirect.ClientSecret,
			TokenURL:     redirect.TokenURL,
		},
	})
	if err != nil {
		c.Set("auth_error", err.Error())
		return err
	}

	if redirect.UseSession {
		if _, err := store.SetSessionB64(c.Request(), c.Response(), body, cookieName, "cookie", sessionStore); err != nil {
			c.Logger().Debug("error save session", err)
		}

		return nil
	}

	// set the cookie
	store.SetCookieB64(c.Response(), body, cookieName, redirect.MapConfigCookie())

	return nil
}
