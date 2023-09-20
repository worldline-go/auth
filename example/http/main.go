package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/worldline-go/initializer"
	"github.com/worldline-go/logz"
)

func main() {
	initializer.Init(
		run,
		initializer.WithMsgf("Starting %s...", os.Getenv("ACTION")),
		initializer.WithOptionsLogz(
			logz.WithCaller(false),
		))
}

func run(ctx context.Context, _ *sync.WaitGroup) error {
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

	provider := providerClient.ActiveProvider()
	if provider == nil {
		return fmt.Errorf("no active provider")
	}

	transport, err := provider.RoundTripper(ctx, http.DefaultTransport)
	if err != nil {
		return fmt.Errorf("creating transport: %w", err)
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}

	log.Info().Msg("Sending request...")

	urlRequest := os.Getenv("ACTION_URL")
	if urlRequest == "" {
		urlRequest = "http://localhost:3000"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlRequest, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resp, err := client.Do(req)
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
