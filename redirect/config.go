package redirect

import (
	"net/http"
	"regexp"

	"github.com/worldline-go/auth/store"
)

type Setting struct {
	AuthURL      string   `cfg:"-"`
	TokenURL     string   `cfg:"-"`
	ClientID     string   `cfg:"-"`
	ClientSecret string   `cfg:"-"`
	Scopes       []string `cfg:"-"`

	// CookieName is the name of the cookie. Default is "auth_" + ClientID.
	CookieName string `cfg:"cookie_name"`
	// MaxAge the number of seconds until the cookie expires.
	MaxAge int `cfg:"max_age"`
	// Path that must exist in the requested URL for the browser to send the Cookie header.
	Path string `cfg:"path"`
	// Domain for defines the host to which the cookie will be sent.
	Domain string `cfg:"domain"`
	// Secure to cookie only sent over HTTPS.
	Secure bool `cfg:"secure"`
	// SameSite for Lax 2, Strict 3, None 4.
	SameSite http.SameSite `cfg:"same_site"`
	// HttpOnly for true for not accessible by JavaScript.
	HttpOnly bool `cfg:"http_only"`

	// Callback is the callback URI.
	Callback string `cfg:"callback"`
	// CallbackSet for setting back original path.
	CallbackSet bool `cfg:"callback_set"`
	// CallbackModify for modify the callback URI, for multiple regex using the first match.
	CallbackModify []RegexPath `cfg:"callback_modify"`
	// BaseURL is the base URL to use for the redirect.
	// Default is the request Host with checking the X-Forwarded-Host header.
	BaseURL string `cfg:"base_url"`
	// Schema is the default schema to use for the redirect if no schema is provided.
	// Default is the https schema.
	Schema string `cfg:"schema"`

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
	// CheckAgentContains for check agent extra settings, default is related with implementation, usually is "Mozilla".
	CheckAgentContains string `cfg:"check_agent_contains"`
}

type RegexPath struct {
	Regex       string `cfg:"regex"`
	Replacement string `cfg:"replacement"`
	rgx         *regexp.Regexp
}

func (r *Setting) MapConfigCookie() store.Config {
	return store.Config{
		Domain:   r.Domain,
		Path:     r.Path,
		MaxAge:   r.MaxAge,
		Secure:   r.Secure,
		SameSite: r.SameSite,
		HttpOnly: r.HttpOnly,
	}
}
