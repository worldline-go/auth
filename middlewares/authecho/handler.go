package authecho

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/worldline-go/auth/claims"

	echojwt "github.com/labstack/echo-jwt/v4"
)

type RedirectSetting struct {
	AuthURL      string `cfg:"auth_url"`
	TokenURL     string `cfg:"token_url"`
	ClientID     string `cfg:"client_id"`
	ClientSecret string `cfg:"client_secret"`

	CookieName string `cfg:"cookie_name"`
	// Callback is the callback URI.
	Callback string `cfg:"callback"`
	// MaxAge for the cookie.
	MaxAge int `cfg:"max_age"`
	// Path for the cookie.
	Path string `cfg:"path"`
	// BaseURL is the base URL to use for the redirect.
	BaseURL string `cfg:"base_url"`
	// Secure is the secure flag for the cookie.
	Secure bool `cfg:"secure"`

	CheckValue string `cfg:"check_value"`
}

// MiddlewareJWT returns a JWT middleware.
// Default claims is *claims.Custom.
func MiddlewareJWT(opts ...Option) echo.MiddlewareFunc {
	var options options
	for _, opt := range opts {
		opt(&options)
	}

	if options.config.NewClaimsFunc == nil {
		options.config.NewClaimsFunc = func(c echo.Context) jwt.Claims {
			var value jwt.Claims

			if options.newClaims == nil {
				value = &claims.Custom{}
			} else {
				value = options.newClaims()
			}

			c.Set("claims", value)

			return value
		}
	}

	if options.redirect != nil {
		if options.redirect.MaxAge == 0 {
			options.redirect.MaxAge = 3600
		}
		if options.redirect.Path == "" {
			options.redirect.Path = "/"
		}

		redirectURI, _ := url.JoinPath(options.redirect.BaseURL, options.redirect.Callback)

		options.config.BeforeFunc = func(c echo.Context) {
			// check user-agent not a browser
			if !strings.Contains(c.Request().UserAgent(), "Mozilla") {
				// not a browser, return
				return
			}

			// check header Authorization is set
			if c.Request().Header.Get("Authorization") != "" {
				// header Authorization is set, no need to set cookie
				return
			}

			if cookie, err := c.Cookie(options.redirect.CookieName); err == nil && cookie.Value != "" {
				// add the access token to the request
				cookieParsed, err := NewCookie(cookie.Value, true)
				if err != nil {
					return
				}

				_ = AddAuthorizationHeader(c, cookieParsed.AccessToken)

				return
			}

			if options.redirect.CheckValue != "" {
				if c.Get(options.redirect.CheckValue) == nil {
					return
				}
			}

			// get the token from the request
			code := c.QueryParam("code")

			if code == "" {
				// no code, continue
				return
			}

			data := url.Values{}
			data.Add("grant_type", "authorization_code")
			data.Add("code", code)
			data.Add("redirect_uri", redirectURI)
			data.Add("client_id", options.redirect.ClientID)
			encodedData := data.Encode()

			req, err := http.NewRequestWithContext(c.Request().Context(), http.MethodPost, options.redirect.TokenURL, strings.NewReader(encodedData))
			if err != nil {
				return
			}

			clientPass := base64.StdEncoding.EncodeToString([]byte(options.redirect.ClientID + ":" + options.redirect.ClientSecret))

			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Add("Authorization", "Basic "+clientPass)
			req.Header.Set("accept", "application/json")

			response, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}

			body, _ := io.ReadAll(response.Body)
			response.Body.Close()

			cookieParsed, err := NewCookie(string(body), false)
			if err != nil {
				return
			}

			_ = AddAuthorizationHeader(c, cookieParsed.AccessToken)

			cookieValue := base64.StdEncoding.EncodeToString(body)
			// set the cookie
			c.SetCookie(&http.Cookie{
				Name:   options.redirect.CookieName,
				Value:  cookieValue,
				Path:   options.redirect.Path,
				MaxAge: options.redirect.MaxAge,
				Secure: options.redirect.Secure,
			})

			c.Set("cookie_"+options.redirect.CookieName, cookieValue)
		}

		options.config.ErrorHandler = func(c echo.Context, err error) error {
			errX := echo.NewHTTPError(http.StatusUnauthorized, "missing or malformed jwt").SetInternal(err)

			// check user-agent not a browser
			if !strings.Contains(c.Request().UserAgent(), "Mozilla") {
				// not a browser, return error
				return errX
			}

			// remove the cookie
			c.SetCookie(&http.Cookie{
				Name:   options.redirect.CookieName,
				Value:  "",
				Path:   options.redirect.Path,
				MaxAge: -1,
				Secure: options.redirect.Secure,
			})

			if options.redirect.CheckValue != "" {
				if c.Get(options.redirect.CheckValue) == nil {
					return errX
				}
			}

			// redirect to login page
			data := url.Values{}
			data.Add("response_type", "code")
			data.Add("state", "state_auth")
			data.Add("redirect_uri", redirectURI)
			data.Add("client_id", options.redirect.ClientID)

			redirect := options.redirect.AuthURL + "?" + data.Encode()
			return c.Redirect(http.StatusTemporaryRedirect, redirect)
		}
	}

	return echojwt.WithConfig(options.config)
}
