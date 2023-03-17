package authecho

import (
	"github.com/worldline-go/auth/store"
)

type RedirectSetting struct {
	AuthURL      string   `cfg:"-"`
	TokenURL     string   `cfg:"-"`
	ClientID     string   `cfg:"-"`
	ClientSecret string   `cfg:"-"`
	Scopes       []string `cfg:"-"`

	// NoClientIDParam is use to not add client_id in the query params.
	NoClientIDParam bool `cfg:"no_client_id_param"`
	// CookieName is the name of the cookie. Default is "auth_" + ClientID.
	CookieName string `cfg:"cookie_name"`
	// Callback is the callback URI.
	Callback string `cfg:"callback"`
	// MaxAge for the cookie.
	MaxAge int `cfg:"max_age"`
	// Path for the cookie.
	Path string `cfg:"path"`
	// Domain for the cookie.
	Domain string `cfg:"domain"`
	// BaseURL is the base URL to use for the redirect.
	// Default is the request Host with checking the X-Forwarded-Host header.
	BaseURL string `cfg:"base_url"`
	// Schema is the default schema to use for the redirect if no schema is provided.
	// Default is the https schema.
	Schema string `cfg:"schema"`
	// Secure is the secure flag for the cookie.
	Secure bool `cfg:"secure"`

	// UseSession is use session instead of cookie.
	UseSession bool `cfg:"use_session"`
	// SessionKey secret key for session.
	SessionKey string `cfg:"session_key"`

	// TokenHeader to add token to header.
	TokenHeader bool `cfg:"token_header"`
	// RefreshToken is use to refresh the token.
	RefreshToken bool `cfg:"refresh_token"`

	CheckValue string `cfg:"check_value"`
	CheckAgent bool   `cfg:"check_agent"`
}

func (r *RedirectSetting) MapConfigCookie() store.Config {
	return store.Config{
		Domain: r.Domain,
		Path:   r.Path,
		MaxAge: r.MaxAge,
		Secure: r.Secure,
	}
}
