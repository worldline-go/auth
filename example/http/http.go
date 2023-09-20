package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/worldline-go/auth"
	"github.com/worldline-go/auth/claims"
	"github.com/worldline-go/initializer"
)

func httpServer(ctx context.Context) error {
	provider := providerServer.ActiveProvider()
	if provider == nil {
		return fmt.Errorf("no active provider")
	}

	keyFunc, err := provider.JWTKeyFunc(auth.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("creating parser: %w", err)
	}

	// use if context not set
	// defer keyFunc.EndBackground()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// check authentication
		authorization := r.Header.Get("Authorization")
		if authorization == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Authorization header is missing"))
			return
		}

		// parse token
		claimsValue := claims.Custom{}
		token, err := keyFunc.Parser(authorization[7:], &claimsValue)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			log.Error().Err(err).Msg("parsing token")
			_, _ = w.Write([]byte("invalid token"))
			return
		}

		log.Info().Msgf("Token: %+v", token.Claims)
		log.Info().Msgf("Claims: %+v", claimsValue)

		log.Info().Msgf("has transaciton role: %v", claimsValue.HasRole("transaction"))

		// log request
		log.Info().Msgf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
		// log headers
		for k, v := range r.Header {
			log.Info().Msgf("%s: %s", k, v)
		}
		// log body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Info().Err(err).Msg("reading body")
		} else {
			log.Info().Msgf("Body: %q", body)
		}

		// write response
		log.Info().Msg("writing response")
		_, _ = w.Write([]byte("hello"))
	})

	server := &http.Server{
		Addr:           ":3000",
		Handler:        mux,
		MaxHeaderBytes: 1 << 20,
	}

	initializer.Shutdown.Add(
		func() error {
			return httpServerShutdown(server)
		},
		initializer.WithShutdownName("http-server"),
	)

	log.Printf("Listening on %s\n", server.Addr)
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Info().Err(err).Msg("server closed")

		return err
	}

	return nil
}

func httpServerShutdown(server *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		return err
	}

	return nil
}
