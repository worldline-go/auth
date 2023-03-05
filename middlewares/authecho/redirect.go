package authecho

import (
	"net/http"
	"net/url"

	"github.com/labstack/echo/v4"
	"github.com/worldline-go/auth/store"
)

func SaveRedirectQueryParams(c echo.Context, cookieName string, redirect *RedirectSetting, sessionStore store.SessionStore) {
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

	if redirect.UseSession {
		if err := store.SetSession(c.Request(), c.Response(), values.Encode(), cookieName+"_code", "query", sessionStore); err != nil {
			c.Logger().Debug("error save session", err)
		}

		return
	}

	store.SetCookie(c.Response(), values.Encode(), cookieName+"_code", redirect.MapConfigCookie())
}

func SetRedirectQueryParams(c echo.Context, cookieName string, redirect *RedirectSetting, sessionStore store.SessionStore) {
	value := ""
	if redirect.UseSession {
		session, _ := sessionStore.Get(c.Request(), cookieName+"_code")
		if session.IsNew {
			return
		}

		var ok bool
		value, ok = session.Values["query"].(string)
		if !ok {
			return
		}
	} else {
		cookie, err := c.Cookie(cookieName + "_code")
		if err != nil {
			return
		}
		value = cookie.Value
	}

	values, err := url.ParseQuery(value)
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

	if redirect.UseSession {
		_ = store.RemoveSession(c.Request(), c.Response(), cookieName+"_code", sessionStore)

		return
	}

	store.RemoveCookie(c.Response(), cookieName+"_code", redirect.MapConfigCookie())
}

func RemoveAuthQueryParams(r *http.Request) {
	q := r.URL.Query()
	q.Del("code")
	q.Del("state")
	q.Del("session_state")
	r.URL.RawQuery = q.Encode()
}

func RedirectURI(r *http.Request, callback, baseURL, schema string) (string, error) {
	if baseURL == "" {
		// check headers of X-Forwarded-Proto and X-Forwarded-Host
		// if they are set, use them to build the redirect uri

		proto := r.Header.Get("X-Forwarded-Proto")
		host := r.Header.Get("X-Forwarded-Host")

		if proto != "" && host != "" {
			r.URL.Scheme = proto
			r.URL.Host = host
		} else {
			// check the host header
			host := r.Host
			if host != "" {
				r.URL.Host = host
				if schema != "" {
					r.URL.Scheme = schema
				} else {
					r.URL.Scheme = "https"
				}
			}
		}
	} else {
		urlParsed, err := url.Parse(baseURL)
		if err != nil {
			return "", err
		}

		r.URL.Scheme = urlParsed.Scheme
		r.URL.Host = urlParsed.Host
	}

	if callback != "" {
		r.URL.Path = callback
	}

	return r.URL.String(), nil
}
