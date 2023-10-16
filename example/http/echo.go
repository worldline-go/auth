package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog/log"
	"github.com/worldline-go/auth/claims"
	"github.com/worldline-go/auth/example/http/docs"
	"github.com/worldline-go/auth/jwks"
	"github.com/worldline-go/auth/pkg/authecho"
	echoSwagger "github.com/worldline-go/echo-swagger"
	"github.com/worldline-go/initializer"
	"github.com/worldline-go/logz/logecho"
	"github.com/ziflex/lecho/v3"
)

type API struct{}

// GetInfoClaim return the claims of the user
//
// @Summary Get info claim
// @Description Get info claim
// @Tags info
// @Accept  json
// @Produce  json
// @Success 200 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /info [get]
// @Security ApiKeyAuth || OAuth2Application || OAuth2Implicit || OAuth2Password || OAuth2AccessCode
func (API) GetInfoClaim(c echo.Context) error {
	claims, ok := c.Get(authecho.KeyClaims).(*claims.Custom)
	if !ok {
		return c.JSON(http.StatusNotFound, map[string]interface{}{"error": "claims not found"})
	}

	return c.JSONBlob(http.StatusOK, claims.Raw)
}

// CheckMyRole check if the user has the role
//
// @Summary Check my role
// @Description Check my role
// @Tags info
// @Accept  json
// @Produce  json
// @Param role path string true "role"
// @Success 200 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /role/{role} [get]
// @Security ApiKeyAuth || OAuth2Application || OAuth2Implicit || OAuth2Password || OAuth2AccessCode
func (API) CheckMyRole(c echo.Context) error {
	claims, ok := c.Get(authecho.KeyClaims).(*claims.Custom)
	if !ok {
		return c.JSON(http.StatusNotFound, map[string]interface{}{"error": "claims not found"})
	}

	role := c.Param("role")
	if claims.HasRole(role) {
		return c.JSON(http.StatusOK, map[string]interface{}{"has_role": true})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{"has_role": false})
}

// CheckMyScope check if the user has the scope
//
// @Summary Check my scope
// @Description Check my scope
// @Tags info
// @Accept  json
// @Produce  json
// @Param scope path string true "scope"
// @Success 200 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /role/{scope} [get]
// @Security ApiKeyAuth || OAuth2Application || OAuth2Implicit || OAuth2Password || OAuth2AccessCode
func (API) CheckMyScope(c echo.Context) error {
	claims, ok := c.Get(authecho.KeyClaims).(*claims.Custom)
	if !ok {
		return c.JSON(http.StatusNotFound, map[string]interface{}{"error": "claims not found"})
	}

	scope := c.Param("scope")
	if claims.HasScope(scope) {
		return c.JSON(http.StatusOK, map[string]interface{}{"has_scope": true})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{"has_scope": false})
}

// PostValue return the body
//
// @Summary Post value
// @Description Post value
// @Tags restricted
// @Accept  json
// @Produce  json
// @Success 200 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /value [post]
// @Security ApiKeyAuth || OAuth2Application || OAuth2Implicit || OAuth2Password || OAuth2AccessCode
func (API) PostValue(c echo.Context) error {
	// get body
	var body map[string]interface{}
	if err := c.Bind(&body); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, body)
}

// Ping return pong
//
// @Summary Ping
// @Description Ping
// @Accept  plain
// @Produce  plain
// @Success 200 {string} string "pong"
// @Router /ping [get]
func (API) Ping(c echo.Context) error {
	return c.String(http.StatusOK, "pong\n")
}

// Echo Server
//
// @title Auth Test API
// @description This is a sample server for out Auth library.
//
// @contant.name worldline-go
// @contant.url https://github.com/worldline-go
//
// @securityDefinitions.apikey	ApiKeyAuth
// @in							header
// @name						Authorization
// @description				Description for what is this security definition being used
//
// @securitydefinitions.oauth2.accessCode	OAuth2AccessCode
// @tokenUrl								[[ .Custom.tokenUrl ]]
// @authorizationUrl						[[ .Custom.authUrl ]]
func echoServer(ctx context.Context) error {
	e := echo.New()
	e.HideBanner = true

	// if noop is true, it will return a fake provider
	provider := providerServer.ActiveProvider()
	if provider == nil {
		return fmt.Errorf("no authentication provider found")
	}

	if err := docs.Info("v0.0.0", provider); err != nil {
		return err
	}

	e.Logger = lecho.New(log.With().Str("component", "server").Logger())

	// show stack trace better
	recoverConfig := middleware.DefaultRecoverConfig
	recoverConfig.LogErrorFunc = func(c echo.Context, err error, stack []byte) error {
		log.Error().Err(err).Msgf("panic: %s", stack)

		return err
	}

	e.Use(
		middleware.Decompress(),
		middleware.CORS(),
		middleware.RecoverWithConfig(recoverConfig),
	)

	e.Use(
		middleware.RequestID(),
		middleware.RequestLoggerWithConfig(logecho.RequestLoggerConfig()),
		logecho.ZerologLogger(),
	)

	// auth middleware
	jwks, err := provider.JWTKeyFunc(jwks.WithContext(ctx))
	if err != nil {
		return err
	}

	// use if context not set
	// defer jwks.EndBackground()

	jwtMiddleware := authecho.MiddlewareJWT(
		authecho.WithKeyFunc(jwks.Keyfunc),
		authecho.WithSkipper(authecho.NewSkipper()),
	)

	api := API{}

	// setup routes
	e.GET("/ping", api.Ping)
	e.GET("/swagger/*", echoSwagger.EchoWrapHandler(func(c *echoSwagger.Config) {
		c.OAuth = &echoSwagger.OAuthConfig{
			ClientId: provider.GetClientIDExternal(),
		}
	}))
	// restricted zone
	e.GET("/info", api.GetInfoClaim, jwtMiddleware)
	e.GET("/role/:role", api.CheckMyRole, jwtMiddleware)
	e.GET("/scope/:scope", api.CheckMyScope, jwtMiddleware)
	// restricted zone with role
	e.POST("/value", api.PostValue,
		jwtMiddleware,
		authecho.MiddlewareRole(
			authecho.WithRoles(""),
		),
	)

	// Graceful shutdown
	initializer.Shutdown.Add(func() error {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		return e.Shutdown(ctx)
	}, initializer.WithShutdownName("echo-server"))

	if err := e.Start(":3000"); err != nil && err != http.ErrServerClosed {
		log.Err(err).Msg("shutting down the server")
	}

	return nil
}
