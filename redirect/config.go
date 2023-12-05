package redirect

import (
	"net/http"
	"regexp"

	"github.com/worldline-go/auth/store"
)

type Setting struct {
	AuthURL      string   `cfg:"-"`
	TokenURL     string   `cfg:"-"`
	LogoutURL    string   `cfg:"-"`
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

	RedirectMatch RedirectMatch `cfg:"redirect_match"`

	// UseSession is use session instead of cookie.
	UseSession bool `cfg:"use_session"`
	// SessionKey secret key for session, if shared with other applications, use a static string, default is random.
	SessionKey string `cfg:"session_key"`
	// SessionPath is the path to store the session, os.TempDir() is the default.
	SessionPath string `cfg:"session_path"`
	// SessionStoreName is the name store for session.
	// Use Store.GetSessionFilesystem to get the store.
	SessionStoreName string `cfg:"session_store_name"`

	// TokenHeader to add token to header.
	TokenHeader bool `cfg:"token_header"`
	// RefreshToken is use to refresh the token.
	RefreshToken bool `cfg:"refresh_token"`

	CheckAgent bool `cfg:"check_agent"`
	// CheckAgentContains for check agent extra settings, default is related with implementation, usually is "Mozilla".
	CheckAgentContains string `cfg:"check_agent_contains"`

	// Information is use to store some information about token.
	Information Information `cfg:"information"`

	// Logout usable with "openid" scope.
	Logout Logout `cfg:"logout"`

	Client *http.Client `cfg:"-"`
}

type Logout struct {
	// Path is the path to logout, like "/logout".
	Path string `cfg:"url"`
	// Redirect is the redirect URL after logout.
	Redirect string `cfg:"redirect"`
}

type Information struct {
	// InformationCookie is use to store some information about token.
	//  - CookieName required want to use this cookie.
	//  - Store as json.
	Cookie InformationCookie `cfg:"cookie"`
}

type InformationCookie struct {
	// Name is the name of the cookie, required want to use this cookie.
	Name     string        `cfg:"name"`
	MaxAge   int           `cfg:"max_age"`
	Path     string        `cfg:"path"`
	Domain   string        `cfg:"domain"`
	Secure   bool          `cfg:"secure"`
	SameSite http.SameSite `cfg:"same_site"`
	// HttpOnly for true for not accessible by JavaScript. Default is false.
	HttpOnly bool `cfg:"http_only"`
	// Map list to store in the cookie like "preferred_username", "given_name", "family_name", "sid", "azp", "aud"
	Map []string `cfg:"values"`
	// Custom map to store in the cookie.
	Custom map[string]interface{} `cfg:"custom"`
	// Roles to store in the cookie as []string.
	Roles bool `cfg:"roles"`
	// Scopes to store in the cookie as []string.
	Scopes bool `cfg:"scopes"`
}

func (r *InformationCookie) MapConfigCookie() store.Config {
	if r.MaxAge == 0 {
		r.MaxAge = 3600
	}
	if r.Path == "" {
		r.Path = "/"
	}

	return store.Config{
		Domain:   r.Domain,
		Path:     r.Path,
		MaxAge:   r.MaxAge,
		Secure:   r.Secure,
		SameSite: r.SameSite,
		HttpOnly: r.HttpOnly,
	}
}

type RegexPath struct {
	Regex       string `cfg:"regex"`
	Replacement string `cfg:"replacement"`
	rgx         *regexp.Regexp
}

type RegexMatch struct {
	Regex string `cfg:"regex"`
	rgx   *regexp.Regexp
}

type RedirectMatch struct {
	Enabled           bool              `cfg:"enabled"`
	NoHeaderKeys      []string          `cfg:"header_keys"`
	NoHeaderKeyValues map[string]string `cfg:"header_key_values"`
	Regex             string            `cfg:"regex"`
	rgx               *regexp.Regexp
}

func (r *Setting) MapConfigCookie() store.Config {
	if r.MaxAge == 0 {
		r.MaxAge = 3600
	}
	if r.Path == "" {
		r.Path = "/"
	}

	return store.Config{
		Domain:   r.Domain,
		Path:     r.Path,
		MaxAge:   r.MaxAge,
		Secure:   r.Secure,
		SameSite: r.SameSite,
		HttpOnly: r.HttpOnly,
	}
}
