package authecho

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
)

type Cookie struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

func ParseCookie(v string, b64 bool) (*Cookie, error) {
	cookieRecord := Cookie{}
	vByte := []byte(v)

	if b64 {
		var err error
		vByte, err = base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, err
		}
	}

	// parse cookie
	if err := json.Unmarshal(vByte, &cookieRecord); err != nil {
		return nil, err
	}

	return &cookieRecord, nil
}

func AddAuthorizationHeader(c echo.Context, token string) error {
	c.Request().Header.Add("Authorization", "Bearer "+token)

	return nil
}

func RecordCookie(c echo.Context, body []byte, cookieName string, redirect *RedirectSetting) string {
	cookieValue := base64.StdEncoding.EncodeToString(body)
	// set the cookie
	c.SetCookie(&http.Cookie{
		Name:   cookieName,
		Value:  cookieValue,
		Domain: redirect.Domain,
		Path:   redirect.Path,
		MaxAge: redirect.MaxAge,
		Secure: redirect.Secure,
	})

	return cookieValue
}

func RecordCookieCode(c echo.Context, value string, cookieName string, redirect *RedirectSetting) {
	// set the cookie
	c.SetCookie(&http.Cookie{
		Name:   cookieName,
		Value:  value,
		Domain: redirect.Domain,
		Path:   redirect.Path,
		MaxAge: redirect.MaxAge,
		Secure: redirect.Secure,
	})
}

func RemoveCookie(c echo.Context, cookieName string, redirect *RedirectSetting) {
	c.SetCookie(&http.Cookie{
		Name:   cookieName,
		Value:  "",
		Domain: redirect.Domain,
		Path:   redirect.Path,
		MaxAge: -1,
		Secure: redirect.Secure,
	})
}

func RecordSession(c echo.Context, body []byte, cookieName string, sessionStore *sessions.FilesystemStore) string {
	cookieValue := base64.StdEncoding.EncodeToString(body)
	// set the cookie
	session, _ := sessionStore.Get(c.Request(), cookieName)
	session.Values["cookie"] = cookieValue

	if err := session.Save(c.Request(), c.Response()); err != nil {
		c.Logger().Debug("save session", err)
	}

	return cookieValue
}

func RecordSessionCode(c echo.Context, value, cookieName string, sessionStore *sessions.FilesystemStore) {
	// set the cookie
	session, _ := sessionStore.Get(c.Request(), cookieName)
	session.Values["code"] = value

	if err := session.Save(c.Request(), c.Response()); err != nil {
		c.Logger().Debug("save session", err)
	}
}

func RemoveSession(c echo.Context, cookieName string, sessionStore *sessions.FilesystemStore) {
	session, _ := sessionStore.Get(c.Request(), cookieName)
	session.Options.MaxAge = -1

	_ = session.Save(c.Request(), c.Response())
}
