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

const (
	authNoopKey       = "auth_noop"
	authIntrospectKey = "auth_introspect"
)

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
			c.Set(authNoopKey, true)
		}

		if introspect {
			c.Set(authIntrospectKey, true)
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
				if v, ok := c.Get(authNoopKey).(bool); ok && v {
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
				if v, ok := c.Get(authNoopKey).(bool); ok && v {
					return auth.NoopKey, nil
				}

				return nil, fmt.Errorf("failed to parse the JWT: %w", err)
			}

			return token, nil
		}
	}

	if introspect {
		options.config.ParseTokenFunc = func(c echo.Context, tokenStr string) (interface{}, error) {
			if v, _ := c.Get(authIntrospectKey).(bool); !v {
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
			Path:     options.redirect.Path,
			Domain:   options.redirect.Domain,
			MaxAge:   options.redirect.MaxAge,
			Secure:   options.redirect.Secure,
			HttpOnly: options.redirect.HttpOnly,
			SameSite: options.redirect.SameSite,
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
					c.Logger().Debugf("not a browser: %v", c.Request().UserAgent())

					return next(c)
				}

				// check header Authorization is set
				if c.Request().Header.Get("Authorization") != "" {
					// header Authorization is set, no need to check cookie
					c.Logger().Debug("header Authorization is set")

					return next(c)
				}

				v64 := ""
				if options.redirect.UseSession {
					if v, err := sessionStore.Get(c.Request(), cookieName); !v.IsNew && err == nil {
						// add the access token to the request
						v64, _ = v.Values["cookie"].(string)
						// c.Logger().Debugf("found session: %v, %v", cookieName, v64)
					}
				} else {
					if cookie, err := c.Cookie(cookieName); err == nil && cookie.Value != "" {
						// add the access token to the request
						v64 = cookie.Value
						// c.Logger().Debugf("found cookie: %v, %v", cookieName, v64)
					}
				}

				if v64 != "" {
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

					c.Set("access_token", cookieParsed.AccessToken)

					if options.redirect.TokenHeader {
						request.SetBearerAuth(c.Request(), cookieParsed.AccessToken)
					}

					c.Logger().Debug("success going to server")

					return next(c)
				}

				// optional feature to skip check
				if options.redirect.CheckValue != "" {
					if c.Get(options.redirect.CheckValue) == nil {
						c.Logger().Debugf("check value not set: %v", options.redirect.CheckValue)

						return next(c)
					}
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
					c.Set("auth_error", err.Error())
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
				// return error
				return errX
			}

			// check user-agent not a browser
			agentContains := options.redirect.CheckAgentContains
			if agentContains != "" {
				agentContains = "Mozilla"
			}

			if options.redirect.CheckAgent && !strings.Contains(c.Request().UserAgent(), agentContains) {
				// not a browser, return error
				return errX
			}

			if options.redirect.UseSession {
				_ = store.RemoveSession(c.Request(), c.Response(), cookieName, sessionStore)
			} else {
				store.RemoveCookie(c.Response(), cookieName, options.redirect.MapConfigCookie())
			}

			if options.redirect.CheckValue != "" {
				if c.Get(options.redirect.CheckValue) == nil {
					return errX
				}
			}

			if errS := c.Get("auth_error"); errS != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, errS.(string))
			}

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
