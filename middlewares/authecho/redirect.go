package authecho

import (
	"net/http"
	"net/url"

	"github.com/labstack/echo/v4"
)

func SaveRedirectQueryParams(c echo.Context, cookieName string, redirect *RedirectSetting) {
	values := url.Values{}

	q := c.Request().URL.Query()
	if q.Has("code") {
		values.Add("code", q.Get("code"))
	}
	if q.Has("state") {
		values.Add("state", q.Get("state"))
	}
	if q.Has("session_state") {
		values.Add("session_state", q.Get("session_state"))
	}
	// remove the cookie
	c.SetCookie(&http.Cookie{
		Name:   cookieName + "_code",
		Value:  values.Encode(),
		Path:   c.Request().URL.Path,
		MaxAge: redirect.MaxAge,
		Secure: redirect.Secure,
	})
}

func SetRedirectQueryParams(c echo.Context, cookieName string, redirect *RedirectSetting) {
	cookie, err := c.Cookie(cookieName + "_code")
	if err != nil {
		return
	}

	values, err := url.ParseQuery(cookie.Value)
	if err != nil {
		return
	}

	q := c.Request().URL.Query()
	if values.Has("code") {
		q.Add("code", values.Get("code"))
	}
	if values.Has("state") {
		q.Add("state", values.Get("state"))
	}
	if values.Has("session_state") {
		q.Add("session_state", values.Get("session_state"))
	}
	c.Request().URL.RawQuery = q.Encode()

	// remove the cookie
	c.SetCookie(&http.Cookie{
		Name:   cookieName + "_code",
		Value:  "",
		Path:   c.Request().URL.Path,
		MaxAge: -1,
		Secure: redirect.Secure,
	})
}

func RemoveAuthQueryParams(r *http.Request) {
	q := r.URL.Query()
	q.Del("code")
	q.Del("state")
	q.Del("session_state")
	r.URL.RawQuery = q.Encode()
}

func RedirectURI(r *http.Request, callback, baseURL string) string {
	redirectURI := ""

	if callback == "" {
		urlParsed, err := url.Parse(baseURL)
		if err != nil {
			return ""
		}

		r.URL.Scheme = urlParsed.Scheme
		r.URL.Host = urlParsed.Host
		redirectURI = r.URL.String()
	} else {
		redirectURI, _ = url.JoinPath(baseURL, callback)
	}

	return redirectURI
}
