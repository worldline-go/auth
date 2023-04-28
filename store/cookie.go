package store

import (
	"encoding/base64"
	"net/http"
)

type Config struct {
	// Domain for defines the host to which the cookie will be sent.
	Domain string `cfg:"domain"`
	// Path that must exist in the requested URL for the browser to send the Cookie header.
	Path string `cfg:"path"`
	// MaxAge the number of seconds until the cookie expires.
	MaxAge int `cfg:"max_age"`
	// Secure to cookie only sent over HTTPS.
	Secure bool `cfg:"secure"`
	// SameSite for Lax 2, Strict 3, None 4.
	SameSite http.SameSite `cfg:"same_site"`
	// HttpOnly for true for not accessible by JavaScript.
	HttpOnly bool `cfg:"http_only"`
}

func GetCookie(r *http.Request, cookieName string) (*http.Cookie, error) {
	return r.Cookie(cookieName)
}

func SetCookieB64(w http.ResponseWriter, body []byte, cookieName string, v Config) string {
	cookieValue := base64.StdEncoding.EncodeToString(body)
	// set the cookie
	SetCookie(w, cookieValue, cookieName, v)

	return cookieValue
}

func SetCookie(w http.ResponseWriter, value string, cookieName string, v Config) {
	// set the cookie
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    value,
		Domain:   v.Domain,
		Path:     v.Path,
		MaxAge:   v.MaxAge,
		Secure:   v.Secure,
		SameSite: v.SameSite,
		HttpOnly: v.HttpOnly,
	})
}

func RemoveCookie(w http.ResponseWriter, cookieName string, v Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Domain:   v.Domain,
		Path:     v.Path,
		MaxAge:   -1,
		Secure:   v.Secure,
		SameSite: v.SameSite,
		HttpOnly: v.HttpOnly,
	})
}
