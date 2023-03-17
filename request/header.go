package request

import (
	"net/http"
	"net/url"
)

// AuthHeaderStyle is a type to set Authorization header style.
type AuthHeaderStyle int

const (
	AuthHeaderStyleBasic AuthHeaderStyle = iota
	AuthHeaderStyleBearerSecret
	AuthHeaderStyleParams
)

// AuthHeader is a function to set Authorization header.
//
// Style must be AuthHeaderStyleBasic or AuthHeaderStyleBearerSecret, otherwise it does nothing.
//
// Default style is AuthHeaderStyleBasic.
func AuthHeader(req *http.Request, clientID, clientSecret string, style AuthHeaderStyle) {
	if req == nil {
		return
	}

	switch style {
	case AuthHeaderStyleBasic:
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	case AuthHeaderStyleBearerSecret:
		SetBearerAuth(req, clientSecret)
	}
}

// AuthParams is a function to set Authorization params in url.Values.
//
// Style must be AuthHeaderStyleParams, otherwise it does nothing.
func AuthParams(clientID, clientSecret string, req *http.Request, style AuthHeaderStyle) {
	if style != AuthHeaderStyleParams {
		return
	}

	query := req.URL.Query()
	if clientID != "" {
		query.Add("client_id", clientID)
	}
	if clientSecret != "" {
		query.Add("client_secret", clientSecret)
	}

	req.URL.RawQuery = query.Encode()
}

// SetBearerAuth sets the Authorization header to use Bearer token.
func SetBearerAuth(r *http.Request, token string) {
	r.Header.Add("Authorization", "Bearer "+token)
}
