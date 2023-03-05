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
func AuthParams(clientID, clientSecret string, uV url.Values, style AuthHeaderStyle) {
	if style != AuthHeaderStyleParams {
		return
	}

	if uV == nil {
		return
	}

	if clientID != "" {
		uV.Set("client_id", clientID)
	}
	if clientSecret != "" {
		uV.Set("client_secret", clientSecret)
	}
}

// SetBearerAuth sets the Authorization header to use Bearer token.
func SetBearerAuth(r *http.Request, token string) {
	r.Header.Add("Authorization", "Bearer "+token)
}
