package main

import (
	"context"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/worldline-go/auth/claims"
	"github.com/worldline-go/auth/middlewares/authecho"
	"github.com/worldline-go/logz"
	"github.com/worldline-go/logz/logecho"
	"github.com/ziflex/lecho/v3"
)

func echoServer(ctx context.Context) error {
	e := echo.New()
	e.HideBanner = true

	e.Logger = lecho.New(logz.LevelWriter(log.Logger.Hook(logz.Hooks.InfoHook), zerolog.InfoLevel))

	e.Use(
		middleware.Decompress(),
		middleware.CORS(),
		middleware.Recover(),
	)

	e.Use(
		middleware.RequestID(),
		middleware.RequestLoggerWithConfig(logecho.RequestLoggerConfig()),
		logecho.ZerologLogger(),
	)

	jwks, err := providerServer.GetJwks(ctx)
	if err != nil {
		return err
	}

	defer jwks.EndBackground()

	e.Use(authecho.MiddlewareJWT(
		authecho.WithKeyFunc(jwks.Keyfunc),
		authecho.WithSkipper(authecho.NewSkipper()),
	))

	e.GET("/ping", func(c echo.Context) error {
		return c.String(http.StatusOK, "pong\n")
	})

	e.GET("/", func(c echo.Context) error {
		claims := c.Get("claims").(*claims.Custom)
		log.Info().Msgf("has transaction role: %v", claims.HasRole("transaction"))
		log.Info().Msgf("has email scope: %v", claims.HasScope("email"))

		log.Info().Msgf("scopes: %v", claims.Scope)

		return c.String(http.StatusOK, "Hello, World!")
	}, authecho.MiddlewareRole("transaction"), authecho.MiddlewareScope("email"))

	shutdown = func() {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		_ = e.Shutdown(ctx)
	}

	if err := e.Start(":3000"); err != nil && err != http.ErrServerClosed {
		log.Err(err).Msg("shutting down the server")
	}

	return nil
}
