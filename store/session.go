package store

import (
	"encoding/base64"
	"net/http"

	"github.com/gorilla/sessions"
)

type SessionStore interface {
	Get(r *http.Request, name string) (*sessions.Session, error)
}

func GetSession(r *http.Request, cookieName string, sessionStore SessionStore) (*sessions.Session, error) {
	return sessionStore.Get(r, cookieName)
}

func SetSessionB64(r *http.Request, w http.ResponseWriter, body []byte, cookieName, valueName string, sessionStore SessionStore) (string, error) {
	cookieValue := base64.StdEncoding.EncodeToString(body)

	if err := SetSession(r, w, cookieValue, cookieName, valueName, sessionStore); err != nil {
		return "", err
	}

	return cookieValue, nil
}

func SetSession(r *http.Request, w http.ResponseWriter, value, cookieName, valueName string, sessionStore SessionStore) error {
	// set the cookie
	session, _ := sessionStore.Get(r, cookieName)
	session.Values[valueName] = value

	if err := session.Save(r, w); err != nil {
		return err
	}

	return nil
}

func RemoveSession(r *http.Request, w http.ResponseWriter, cookieName string, sessionStore SessionStore) error {
	session, _ := sessionStore.Get(r, cookieName)
	session.Options.MaxAge = -1

	return session.Save(r, w)
}
