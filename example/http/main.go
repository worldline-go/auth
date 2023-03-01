package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/rytsh/liz/utils/shutdown"
	"github.com/worldline-go/logz"
)

func main() {
	logz.InitializeLog(logz.WithCaller(false))

	exitCode := 0
	ctx, ctxCancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}
	defer func() {
		wg.Wait()
		// recover from panic if one occured to prevent os.Exit
		if r := recover(); r != nil {
			log.Fatal().Msgf("%v", r)
		}

		os.Exit(exitCode)
	}()

	defer ctxCancel()

	wg.Add(1)
	go func() {
		defer wg.Done()

		chTerm := make(chan os.Signal, 1)
		signal.Notify(chTerm, os.Interrupt)

		select {
		case <-ctx.Done():
		case <-chTerm:
			log.Warn().Msg("received shutdown signal")
			exitCode = 1
			ctxCancel()
		}

		shutdown.Global.Run()
	}()

	if err := run(ctx); err != nil {
		log.Err(err).Msg("run failed")
		exitCode = 1
	}
}

func run(ctx context.Context) error {
	var runFn func(context.Context) error

	vAction := os.Getenv("ACTION")

	switch vAction {
	case "server-http":
		runFn = httpServer
	case "server-echo":
		runFn = echoServer
	case "client":
		runFn = httpClient
	default:
		return fmt.Errorf("unknown action: %s", os.Getenv("ACTION"))
	}

	return runFn(ctx)
}

func httpClient(ctx context.Context) error {
	log.Info().Msg("Creating client...")

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: providerClient.RoundTripperMust(ctx, http.DefaultTransport),
	}

	log.Info().Msg("Sending request...")

	urlRequest := os.Getenv("ACTION_URL")
	if urlRequest == "" {
		urlRequest = "http://localhost:3000"
	}

	req, err := http.NewRequest(http.MethodGet, urlRequest, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resp, err := client.Do(req.WithContext(context.Background()))
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading body: %w", err)
	}

	log.Info().Msgf("Body: %q", body)

	// print headers
	// log headers
	for k, v := range resp.Header {
		log.Info().Msgf("Header [%s: %s]", k, v)
	}

	// status code
	log.Info().Msgf("Status: %s", resp.Status)

	return nil
}
