package authecho

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
)

// DefaultExpireDuration is the default duration to check if the access token is about to expire.
var DefaultExpireDuration = time.Second * 10

// IsRefreshNeed checks if the access token is about to expire.
func IsRefreshNeed(accessToken string) (bool, error) {
	claims := jwt.RegisteredClaims{}

	_, _, err := jwt.NewParser().ParseUnverified(accessToken, &claims)
	if err != nil {
		return false, err
	}

	return !claims.VerifyExpiresAt(time.Now().Add(DefaultExpireDuration), false), nil
}

// RefreshToken refreshes the access token and set the cookie.
func RefreshToken(c echo.Context, token, cookieName string, oldCookieValue string, redirect *RedirectSetting, sessionStore *sessions.FilesystemStore) (*Cookie, error) {
	data := url.Values{}
	data.Add("grant_type", "refresh_token")
	data.Add("client_id", redirect.ClientID)
	data.Add("refresh_token", token)
	encodedData := data.Encode()

	req, err := http.NewRequestWithContext(c.Request().Context(), http.MethodPost, redirect.TokenURL, strings.NewReader(encodedData))
	if err != nil {
		return nil, err
	}

	if redirect.ClientSecret != "" {
		clientPass := base64.StdEncoding.EncodeToString([]byte(redirect.ClientID + ":" + redirect.ClientSecret))
		req.Header.Add("Authorization", "Basic "+clientPass)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("accept", "application/json")

	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	body, _ := io.ReadAll(response.Body)
	response.Body.Close()

	if !(response.StatusCode >= 200 && response.StatusCode < 300) {
		return nil, fmt.Errorf(string(body))
	}

	// parse body to cookie
	cookieParsed, err := ParseCookie(string(body), false)
	if err != nil {
		return nil, err
	}

	if redirect.UseSession {
		RecordSession(c, body, cookieName, sessionStore)

		return cookieParsed, nil
	}

	// set the cookie
	cookieValue := RecordCookie(c, body, cookieName, redirect)

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

	data := url.Values{}
	data.Add("grant_type", "authorization_code")
	data.Add("code", code)
	data.Add("redirect_uri", redirectURI)
	data.Add("client_id", redirect.ClientID)
	encodedData := data.Encode()

	req, err := http.NewRequestWithContext(c.Request().Context(), http.MethodPost, redirect.TokenURL, strings.NewReader(encodedData))
	if err != nil {
		c.Set("auth_error", err.Error())
		return err
	}

	if redirect.ClientSecret != "" {
		clientPass := base64.StdEncoding.EncodeToString([]byte(redirect.ClientID + ":" + redirect.ClientSecret))
		req.Header.Add("Authorization", "Basic "+clientPass)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("accept", "application/json")

	response, err := http.DefaultClient.Do(req)
	if err != nil {
		c.Set("auth_error", err.Error())
		return err
	}

	body, _ := io.ReadAll(response.Body)
	response.Body.Close()

	if !(response.StatusCode >= 200 && response.StatusCode < 300) {
		c.Set("auth_error", string(body))
		return fmt.Errorf(string(body))
	}

	if redirect.UseSession {
		RecordSession(c, body, cookieName, sessionStore)

		return nil
	}

	// set the cookie
	RecordCookie(c, body, cookieName, redirect)

	return nil
}
