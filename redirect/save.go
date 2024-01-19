package redirect

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"

	"github.com/worldline-go/auth/store"
)

type RedirectValue struct {
	Path  string `json:"path,omitempty"`
	Query string `json:"query,omitempty"`
	State string `json:"state,omitempty"`
}

func (t *RedirectValue) Marshal() ([]byte, error) {
	return json.Marshal(t)
}

func (t *RedirectValue) Unmarshal(data []byte) error {
	return json.Unmarshal(data, t)
}

var (
	redirectPostfix    = "_redirect"
	redirectSessionKey = "redirect"
)

func SaveRedirect(r *http.Request, w http.ResponseWriter, cookieName string, redirect *Setting, sessionStore store.SessionStore) (RedirectValue, error) {
	value := RedirectValue{}
	// query params
	value.Query = saveQueryParams(r)

	// redirect path
	value.Path = saveredirectPath(r, redirect)

	// state
	var err error
	value.State, err = store.NewState()
	if err != nil {
		return value, fmt.Errorf("error generate state, %w", err)
	}

	valueMarshal, err := value.Marshal()
	if err != nil {
		return value, fmt.Errorf("error marshal value, %w", err)
	}

	return value, SaveValue(r, w, cookieName, redirectPostfix, redirectSessionKey, redirect, sessionStore, valueMarshal)
}

func LoadRedirect(r *http.Request, w http.ResponseWriter, cookieName string, redirect *Setting, sessionStore store.SessionStore) (RedirectValue, error) {
	value, err := LoadValue(r, w, cookieName, redirectPostfix, redirectSessionKey, redirect, sessionStore)
	if err != nil {
		return RedirectValue{}, err
	}

	rValue := RedirectValue{}
	if err := rValue.Unmarshal(value); err != nil {
		return RedirectValue{}, fmt.Errorf("error load value, %w", err)
	}

	return rValue, nil
}

// SetRedirect set to request path and query params.
func SetRedirect(r *http.Request, redirect *Setting, rValue RedirectValue) error {
	// query params
	queryParams, err := url.ParseQuery(rValue.Query)
	if err != nil {
		return fmt.Errorf("error parseQuery, %w", err)
	}

	if redirect.CallbackSet {
		r.URL.RawQuery = queryParams.Encode()
	} else {
		q := r.URL.Query()
		if queryParams.Has("code") {
			q.Add("code", queryParams.Get("code"))
		}
		if queryParams.Has("state") {
			q.Add("state", queryParams.Get("state"))
		}
		if queryParams.Has("session_state") {
			q.Add("session_state", queryParams.Get("session_state"))
		}
		r.URL.RawQuery = q.Encode()
	}

	// path
	path := r.URL.Path
	if redirect.CallbackSet {
		path = rValue.Path
	}

	for i := range redirect.CallbackModify {
		if redirect.CallbackModify[i].rgx == nil {
			rgx, err := regexp.Compile(redirect.CallbackModify[i].Regex)
			if err != nil {
				return fmt.Errorf("error compile regex, %w", err)
			}
			redirect.CallbackModify[i].rgx = rgx
		}

		prePath := path
		path = redirect.CallbackModify[i].rgx.ReplaceAllString(path, redirect.CallbackModify[i].Replacement)

		// first match
		if prePath != path {
			break
		}
	}

	r.URL.Path = path

	return nil
}

func RemoveRedirect(r *http.Request, w http.ResponseWriter, cookieName string, redirect *Setting, sessionStore store.SessionStore) error {
	return RemoveValue(r, w, cookieName, redirectPostfix, redirect, sessionStore)
}

func saveQueryParams(r *http.Request) string {
	values := url.Values{}

	q := r.URL.Query()
	if q.Has("code") {
		values.Add("code", q.Get("code"))
	}
	if q.Has("state") {
		values.Add("state", q.Get("state"))
	}
	if q.Has("session_state") {
		values.Add("session_state", q.Get("session_state"))
	}

	return values.Encode()
}

func saveredirectPath(r *http.Request, redirect *Setting) string {
	if !redirect.CallbackSet {
		return ""
	}

	return r.URL.Path
}

func RemoveAuthQueryParams(r *http.Request) {
	q := r.URL.Query()
	q.Del("code")
	q.Del("state")
	q.Del("session_state")
	r.URL.RawQuery = q.Encode()
}

// SaveValue save the cookie/session.
func SaveValue(r *http.Request, w http.ResponseWriter, cookieName, postfix, sessionKey string, redirect *Setting, sessionStore store.SessionStore, value []byte) error {
	if redirect.UseSession {
		_, err := store.SetSessionB64(r, w, value, cookieName+postfix, sessionKey, sessionStore)

		return err
	}

	store.SetCookieB64(w, value, cookieName+postfix, redirect.MapConfigCookie())

	return nil
}

// LoadValue load the cookie/session.
func LoadValue(r *http.Request, w http.ResponseWriter, cookieName, postfix, sessionKey string, redirect *Setting, sessionStore store.SessionStore) ([]byte, error) {
	value := ""
	if redirect.UseSession {
		session, _ := sessionStore.Get(r, cookieName+postfix)
		if session.IsNew {
			return nil, nil
		}

		var ok bool
		value, ok = session.Values[sessionKey].(string)
		if !ok {
			return nil, fmt.Errorf("sessionKey value not found")
		}
	} else {
		cookie, err := r.Cookie(cookieName + postfix)
		if err != nil {
			return nil, fmt.Errorf("error cookie read, %w", err)
		}
		value = cookie.Value
	}

	// base64 decode
	valueDecode, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("error base64 decode, %w", err)
	}

	return valueDecode, nil
}

// RemoveValue remove the cookie/session.
func RemoveValue(r *http.Request, w http.ResponseWriter, cookieName, postfix string, redirect *Setting, sessionStore store.SessionStore) error {
	if redirect.UseSession {
		return store.RemoveSession(r, w, cookieName+postfix, sessionStore)
	}

	store.RemoveCookie(w, cookieName+postfix, redirect.MapConfigCookie())

	return nil
}
