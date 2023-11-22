package authecho

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog/log"
	"github.com/worldline-go/auth"
	"github.com/worldline-go/auth/claims"
	"github.com/worldline-go/auth/redirect"
	"github.com/worldline-go/auth/request"
	"github.com/worldline-go/auth/store"

	echojwt "github.com/labstack/echo-jwt/v4"
)

var (
	// KeyClaims hold parsed claims in the echo context.
	//
	// Default claims is *claims.Custom.
	KeyClaims = "claims"
	// KeyToken hold parsed *jwt.Token in the echo context.
	//
	// This is default key for echo-jwt's ContextKey if not set.
	KeyToken = "token"
	// KeyAccessToken hold the access token in the echo context.
	KeyAccessToken = "access_token"
	// KeySkipper is true if the jwt middleware skipped.
	KeySkipper = "skipped"

	// KeyAuthNoop hold true if the provider is noop.
	KeyAuthNoop       = "auth_noop"
	KeyAuthIntrospect = "auth_introspect"

	// KeyAuthError internal error for code token get, str format.
	KeyAuthError = "auth_error"

	KeyClearCookieOnJWTKIDError = "clear_cookie_on_jwt_kid_error"
	// KeyDisableRedirect is true if the redirection is disabled.
	KeyDisableRedirect = "disable_redirect"
	// KeyDisableRedirectWithCookie is true redirection disabled and removed cookie.
	KeyDisableRedirectWithCookie = "disable_redirect_with_cookie"
)

func getOptions(opts ...Option) options {
	var options options
	for _, opt := range opts {
		opt(&options)
	}

	// add default skipper key
	if options.config.Skipper != nil {
		skipper := options.config.Skipper

		options.config.Skipper = func(c echo.Context) bool {
			v := skipper(c)
			if v {
				c.Set(KeySkipper, true)
			}

			return v
		}
	}

	if options.config.ContextKey == "" {
		options.config.ContextKey = KeyToken
	}

	if options.config.NewClaimsFunc == nil {
		options.config.NewClaimsFunc = func(c echo.Context) jwt.Claims {
			var value jwt.Claims

			if options.newClaims == nil {
				value = &claims.Custom{}
			} else {
				value = options.newClaims()
			}

			c.Set(KeyClaims, value)

			return value
		}
	}

	// options.config.SuccessHandler = func(c echo.Context) {}

	// is it noop?
	noop := options.noop
	introspect := false

	if options.config.KeyFunc != nil {
		v, _ := options.config.KeyFunc(&jwt.Token{})
		switch v {
		case auth.NoopKey:
			options.noop = true
			noop = true
		case auth.IntrospectKey:
			introspect = true
		}
	}

	options.config.BeforeFunc = func(c echo.Context) {
		if noop {
			c.Set(KeyAuthNoop, true)
		}

		if introspect {
			c.Set(KeyAuthIntrospect, true)
		}
	}

	options.config.TokenLookup = "header:Authorization:Bearer "
	if noop {
		// set the custom token lookup function after the default functions
		extractors, err := echojwt.CreateExtractors(options.config.TokenLookup)
		if err != nil {
			panic(err) // should never happen
		}

		options.config.TokenLookup = "unset:unset"
		options.config.TokenLookupFuncs = []middleware.ValuesExtractor{
			func(c echo.Context) ([]string, error) {
				if v, ok := c.Get(KeyAuthNoop).(bool); ok && v {
					return []string{auth.NoopKey}, nil
				}

				return nil, fmt.Errorf("skip")
			},
		}
		options.config.TokenLookupFuncs = append(extractors, options.config.TokenLookupFuncs...)

		jwtParser := jwt.NewParser()
		options.config.ParseTokenFunc = func(c echo.Context, tokenStr string) (interface{}, error) {
			token, _, err := jwtParser.ParseUnverified(tokenStr, options.config.NewClaimsFunc(c))
			if err != nil {
				// ignore error if noop
				if v, ok := c.Get(KeyAuthNoop).(bool); ok && v {
					return auth.NoopKey, nil
				}

				return nil, fmt.Errorf("failed to parse the JWT: %w", err)
			}

			return token, nil
		}
	}

	if introspect {
		options.config.ParseTokenFunc = func(c echo.Context, tokenStr string) (interface{}, error) {
			if v, _ := c.Get(KeyAuthIntrospect).(bool); !v {
				return nil, fmt.Errorf("invalid auth")
			}

			if options.parser == nil {
				return nil, fmt.Errorf("parser function not set")
			}

			return options.parser(tokenStr, options.config.NewClaimsFunc(c))
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

	if !options.noop && options.redirect != nil {
		if options.redirect.MaxAge == 0 {
			options.redirect.MaxAge = 3600
		}
		if options.redirect.Path == "" {
			options.redirect.Path = "/"
		}

		if options.redirect.CheckAgentContains == "" {
			options.redirect.CheckAgentContains = "Mozilla"
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

		sessionStore := sessions.NewFilesystemStore(options.redirect.SessionPath, sessionKey)
		// maxlength
		sessionStore.MaxLength(1 << 20)
		sessionStore.Options = &sessions.Options{
			Path:     options.redirect.Path,
			Domain:   options.redirect.Domain,
			MaxAge:   options.redirect.MaxAge,
			Secure:   options.redirect.Secure,
			HttpOnly: options.redirect.HttpOnly,
			SameSite: options.redirect.SameSite,
		}
		if options.redirect.SessionStoreName != "" {
			Store.AddSessionFilesystem(options.redirect.SessionStoreName, sessionStore)
		}

		// use as default token extractor
		options.config.TokenLookupFuncs = []middleware.ValuesExtractor{
			func(c echo.Context) ([]string, error) {
				get, ok := c.Get(KeyAccessToken).(string)
				if !ok {
					return nil, fmt.Errorf("access_token not set")
				}

				return []string{get}, nil
			},
		}

		functions = append(functions, func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(c echo.Context) error {
				if options.redirect.Logout.Path != "" && c.Request().URL.Path == options.redirect.Logout.Path {
					logoutURL, err := url.Parse(options.redirect.LogoutURL)
					if err != nil {
						return c.String(http.StatusFailedDependency, err.Error())
					}

					redirectURL := options.redirect.Logout.Redirect

					query := logoutURL.Query()

					v64 := getTokenFromCookie(c, cookieName, options.redirect, sessionStore)
					if v64 != "" {
						cookieParsed, err := store.Parse(v64, store.WithBase64(true))
						if err != nil {
							return c.String(http.StatusFailedDependency, err.Error())
						}

						query.Set("id_token_hint", cookieParsed.IDToken)
					}

					// query.Set("client_id", options.redirect.ClientID)
					query.Set("post_logout_redirect_uri", redirectURL)
					logoutURL.RawQuery = query.Encode()

					// clear cookies
					clearCookies(c.Request(), c.Response(), options.redirect, cookieName, sessionStore)
					// redirect to logout page
					return c.Redirect(http.StatusTemporaryRedirect, logoutURL.String())
				}

				// check user-agent not a browser
				if options.redirect.CheckAgent && !strings.Contains(c.Request().UserAgent(), "Mozilla") {
					// not a browser, return
					c.Logger().Debugf("not a browser: %v", c.Request().UserAgent())

					return next(c)
				}

				// check header Authorization is set
				if c.Request().Header.Get("Authorization") != "" {
					// header Authorization is set, no need to check cookie
					c.Logger().Debug("header Authorization is set")

					return next(c)
				}

				// get token from cookie
				v64 := getTokenFromCookie(c, cookieName, options.redirect, sessionStore)

				if v64 != "" {
					c.Set(KeyClearCookieOnJWTKIDError, true)
					// add the access token to the request
					cookieParsed, err := store.Parse(v64, store.WithBase64(true))
					if err != nil {
						c.Logger().Debugf("failed ParseCookie: %v", err)

						return next(c)
					}

					if options.redirect.RefreshToken {
						ok, err := auth.IsRefreshNeed(cookieParsed.AccessToken)
						if err != nil {
							c.Logger().Debugf("failed IsRefreshNeed: %v", err)

							return next(c)
						}

						// refresh token
						if ok {
							if cookieParsedNew, err := redirect.RefreshToken(c.Request().Context(), c.Request(), c.Response(), cookieParsed.RefreshToken, cookieName, v64, options.redirect, sessionStore); err != nil {
								c.Logger().Debugf("failed RefreshToken: %v", err)
							} else {
								cookieParsed = cookieParsedNew
								c.Logger().Debug("token refreshed")
							}
						}
					}

					c.Set(KeyAccessToken, cookieParsed.AccessToken)

					if options.redirect.TokenHeader {
						request.SetBearerAuth(c.Request(), cookieParsed.AccessToken)
					}

					c.Logger().Debug("success going to server")

					return next(c)
				}

				// check header has special value to not redirect
				if v, _ := c.Get(KeyDisableRedirect).(bool); v {
					return next(c)
				} else if v, _ := c.Get(KeyDisableRedirectWithCookie).(bool); v {
					return next(c)
				}

				// get the token from the request
				code := c.QueryParam("code")
				if code == "" {
					// no code, continue
					return next(c)
				}

				rValue, err := redirect.LoadRedirect(c.Request(), c.Response(), cookieName, options.redirect, sessionStore)
				if err != nil {
					c.Logger().Errorf("failed LoadRedirect: %v", err)

					return next(c)
				}

				if c.QueryParam("state") != rValue.State {
					c.Logger().Error("failed to state check")

					return next(c)
				}

				// remove code from query params to prevent goes to authentication call
				redirect.RemoveAuthQueryParams(c.Request())
				if err := redirect.CodeToken(c.Request().Context(), c.Request(), c.Response(), code, cookieName, options.redirect, sessionStore); err != nil {
					c.Set(KeyAuthError, err.Error())
					c.Logger().Errorf("failed CodeToken: %v", err)

					return next(c)
				}

				// set back the default redirect values
				if err := redirect.SetRedirect(c.Request(), options.redirect, rValue); err != nil {
					c.Logger().Errorf("failed SetRedirect: %v", err)
				}
				// remove redirection cookie
				if err := redirect.RemoveRedirect(c.Request(), c.Response(), cookieName, options.redirect, sessionStore); err != nil {
					c.Logger().Errorf("failed RemoveRedirect: %v", err)
				}

				c.Logger().Debugf("success redirect to: %v", c.Request().URL.String())

				// redirect to the callback but respose already committed
				return c.Redirect(http.StatusTemporaryRedirect, c.Request().URL.String())
			}
		})

		options.config.ErrorHandler = func(c echo.Context, err error) error {
			errX := echo.NewHTTPError(http.StatusUnauthorized, "missing or malformed jwt").SetInternal(err)
			// check error in jwt middleware
			if errors.Is(err, keyfunc.ErrJWKAlgMismatch) || errors.Is(err, keyfunc.ErrKID) || errors.Is(err, keyfunc.ErrKIDNotFound) {
				// clear cookie if it comes from our cookie
				if v, _ := c.Get(KeyClearCookieOnJWTKIDError).(bool); v {
					clearCookies(c.Request(), c.Response(), options.redirect, cookieName, sessionStore)
				}

				// return error
				return errX
			}

			if options.redirect.RedirectMatch.Enabled {
				// check regex match
				ok, err := redirect.RegexCheck(c.Request(), &options.redirect.RedirectMatch)
				if err != nil {
					c.Logger().Errorf("failed RegexCheck: %v", err)
				}

				if !ok {
					return echo.NewHTTPError(http.StatusProxyAuthRequired, errX.Error())
				}
			}

			// check header has special value to not redirect
			if v, _ := c.Get(KeyDisableRedirect).(bool); v {
				return errX
			}

			// check user-agent not a browser
			if options.redirect.CheckAgent && !strings.Contains(c.Request().UserAgent(), options.redirect.CheckAgentContains) {
				// not a browser, return error
				return errX
			}

			// browser part

			// clear cookies
			clearCookies(c.Request(), c.Response(), options.redirect, cookieName, sessionStore)

			// check header has special value to not redirect
			if v, _ := c.Get(KeyDisableRedirectWithCookie).(bool); v {
				return errX
			}

			// check if problem in authentication
			if errS := c.Get(KeyAuthError); errS != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, errS.(string))
			}

			// try to login again

			// to set back again after authentication complete
			redirectValue, err := redirect.SaveRedirect(c.Request(), c.Response(), cookieName, options.redirect, sessionStore)
			if err != nil {
				log.Error().Err(err).Msg("failed SaveRedirect")
			}

			// remove auth query params to prevent goes to authentication call
			redirect.RemoveAuthQueryParams(c.Request())
			redirectURI, errR := redirect.URI(c.Request().Clone(c.Request().Context()), options.redirect.Callback, options.redirect.BaseURL, options.redirect.Schema)
			if errR != nil {
				return echo.NewHTTPError(http.StatusFailedDependency, errR.Error())
			}

			// redirect to login page
			// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
			data := url.Values{}
			data.Add("response_type", "code")
			data.Add("state", redirectValue.State)
			data.Add("redirect_uri", redirectURI)
			data.Add("client_id", options.redirect.ClientID)
			if options.redirect.Scopes != nil {
				data.Add("scope", strings.Join(options.redirect.Scopes, " "))
			}

			redirect := options.redirect.AuthURL + "?" + data.Encode()

			return c.Redirect(http.StatusTemporaryRedirect, redirect)
		}
	}

	return append(functions, echojwt.WithConfig(options.config))
}

func clearCookies(r *http.Request, w http.ResponseWriter, redirectSetting *redirect.Setting, cookieName string, sessionStore store.SessionStore) {
	// clear cookies
	if redirectSetting.UseSession {
		_ = store.RemoveSession(r, w, cookieName, sessionStore)
	} else {
		store.RemoveCookie(w, cookieName, redirectSetting.MapConfigCookie())
	}

	if redirectSetting.Information.Cookie.Name != "" {
		store.RemoveCookie(w, redirectSetting.Information.Cookie.Name, redirectSetting.Information.Cookie.MapConfigCookie())
	}
}

func getTokenFromCookie(c echo.Context, cookieName string, redirectSetting *redirect.Setting, sessionStore store.SessionStore) string {
	if redirectSetting.UseSession {
		if v, err := sessionStore.Get(c.Request(), cookieName); !v.IsNew && err == nil {
			// add the access token to the request
			v64, _ := v.Values["cookie"].(string)

			// c.Logger().Debugf("found session: %v, %v", cookieName, v64)
			return v64
		}

		return ""
	}

	if cookie, err := c.Cookie(cookieName); err == nil && cookie.Value != "" {
		// add the access token to the request
		v64 := cookie.Value
		// c.Logger().Debugf("found cookie: %v, %v", cookieName, v64)

		return v64
	}

	return ""
}
