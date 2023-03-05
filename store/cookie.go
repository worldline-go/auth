package store

import (
	"encoding/base64"
	"net/http"
)

type Config struct {
	Domain string `cfg:"domain"`
	Path   string `cfg:"path"`
	MaxAge int    `cfg:"max_age"`
	Secure bool   `cfg:"secure"`
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
		Name:   cookieName,
		Value:  value,
		Domain: v.Domain,
		Path:   v.Path,
		MaxAge: v.MaxAge,
		Secure: v.Secure,
	})
}

func RemoveCookie(w http.ResponseWriter, cookieName string, v Config) {
	http.SetCookie(w, &http.Cookie{
		Name:   cookieName,
		Value:  "",
		Domain: v.Domain,
		Path:   v.Path,
		MaxAge: -1,
		Secure: v.Secure,
	})
}
