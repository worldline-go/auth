package authecho

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/worldline-go/auth/claims"

	echojwt "github.com/labstack/echo-jwt/v4"
)

type RedirectSetting struct {
	AuthURL      string `cfg:"-"`
	TokenURL     string `cfg:"-"`
	ClientID     string `cfg:"-"`
	ClientSecret string `cfg:"-"`

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

func getOptions(opts ...Option) options {
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

	options.config.SuccessHandler = func(c echo.Context) {
		if options.claimsHeader != nil {
			options.claimsHeader.SetHeaders(c)
		}
	}

	return options
}

// MiddlewareJWT returns a JWT middleware.
// Default claims is *claims.Custom.
//
// WithRedirect option not usable in this function.
func MiddlewareJWT(opts ...Option) echo.MiddlewareFunc {
	options := getOptions(opts...)

	return echojwt.WithConfig(options.config)
}

// MiddlewareJWTWithRedirection returns a JWT middleware with usable redirection option.
// Default claims is *claims.Custom.
//
// Redirection returns 2 middleware functions.
func MiddlewareJWTWithRedirection(opts ...Option) []echo.MiddlewareFunc {
	options := getOptions(opts...)

	functions := []echo.MiddlewareFunc{}

	if options.redirect != nil {
		if options.redirect.MaxAge == 0 {
			options.redirect.MaxAge = 3600
		}
		if options.redirect.Path == "" {
			options.redirect.Path = "/"
		}

		cookieName := options.redirect.CookieName
		if cookieName == "" {
			cookieName = "auth_" + options.redirect.ClientID
		}

		var sessionKey []byte
		if options.redirect.SessionKey == "" {
			sessionKey = []byte(options.redirect.SessionKey)
		} else {
			sessionKey = securecookie.GenerateRandomKey(32)
		}

		sessionStore := sessions.NewFilesystemStore("", sessionKey)
		// maxlength
		sessionStore.MaxLength(1 << 20)
		sessionStore.Options = &sessions.Options{
			Path:   options.redirect.Path,
			Domain: options.redirect.Domain,
			MaxAge: options.redirect.MaxAge,
			Secure: options.redirect.Secure,
		}

		// use as default token extractor
		options.config.TokenLookupFuncs = []middleware.ValuesExtractor{
			func(c echo.Context) ([]string, error) {
				get, ok := c.Get("access_token").(string)
				if !ok {
					return nil, fmt.Errorf("access_token not set")
				}

				return []string{get}, nil
			},
		}

		functions = append(functions, func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(c echo.Context) error {
				// check user-agent not a browser
				if options.redirect.CheckAgent && !strings.Contains(c.Request().UserAgent(), "Mozilla") {
					// not a browser, return
					return next(c)
				}

				// check header Authorization is set
				if c.Request().Header.Get("Authorization") != "" {
					// header Authorization is set, no need to check cookie
					return next(c)
				}

				v64 := ""
				if options.redirect.UseSession {
					if v, err := sessionStore.Get(c.Request(), cookieName); !v.IsNew && err == nil {
						// add the access token to the request
						v64 = v.Values["cookie"].(string)
					}
				} else {
					if cookie, err := c.Cookie(cookieName); err == nil && cookie.Value != "" {
						// add the access token to the request
						v64 = cookie.Value
					}
				}

				if v64 != "" {
					// add the access token to the request
					cookieParsed, err := ParseCookie(v64, true)
					if err != nil {
						c.Logger().Debugf("failed ParseCookie: %v", err)
						return next(c)
					}

					if options.redirect.RefreshToken {
						ok, err := IsRefreshNeed(cookieParsed.AccessToken)
						if err != nil {
							c.Logger().Debugf("failed IsRefreshNeed: %v", err)
							return next(c)
						}

						// refresh token
						if ok {
							if cookieParsedNew, err := RefreshToken(c, cookieParsed.RefreshToken, cookieName, v64, options.redirect, sessionStore); err != nil {
								c.Logger().Debugf("failed RefreshToken: %v", err)
							} else {
								cookieParsed = cookieParsedNew
							}
						}
					}

					c.Set("access_token", cookieParsed.AccessToken)

					if options.redirect.TokenHeader {
						_ = AddAuthorizationHeader(c, cookieParsed.AccessToken)
					}

					return next(c)
				}

				if options.redirect.CheckValue != "" {
					if c.Get(options.redirect.CheckValue) == nil {
						return next(c)
					}
				}

				// get the token from the request
				code := c.QueryParam("code")

				if code == "" || c.QueryParam("state") != "state_auth" {
					// no code, continue
					return next(c)
				}

				// remove code from query params
				RemoveAuthQueryParams(c.Request())
				if err := CodeToken(c, code, cookieName, options.redirect, sessionStore); err != nil {
					c.Logger().Debugf("failed CodeToken: %v", err)

					return next(c)
				}

				// set back the query params
				SetRedirectQueryParams(c, cookieName, options.redirect, sessionStore)

				// redirect to the callback but respose already committed
				return c.Redirect(http.StatusTemporaryRedirect, c.Request().URL.String())
			}
		})

		options.config.ErrorHandler = func(c echo.Context, err error) error {
			errX := echo.NewHTTPError(http.StatusUnauthorized, "missing or malformed jwt").SetInternal(err)

			// check user-agent not a browser
			if options.redirect.CheckAgent && !strings.Contains(c.Request().UserAgent(), "Mozilla") {
				// not a browser, return error
				return errX
			}

			if options.redirect.UseSession {
				RemoveSession(c, cookieName, sessionStore)
			} else {
				RemoveCookie(c, cookieName, options.redirect)
			}

			if options.redirect.CheckValue != "" {
				if c.Get(options.redirect.CheckValue) == nil {
					return errX
				}
			}

			if errS := c.Get("auth_error"); errS != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, errS.(string))
			}

			SaveRedirectQueryParams(c, cookieName, options.redirect, sessionStore)
			RemoveAuthQueryParams(c.Request())

			redirectURI, errR := RedirectURI(c.Request().Clone(c.Request().Context()), options.redirect.Callback, options.redirect.BaseURL, options.redirect.Schema)
			if errR != nil {
				return echo.NewHTTPError(http.StatusFailedDependency, errR.Error())
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

	return append(functions, echojwt.WithConfig(options.config))
}
