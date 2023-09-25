package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/worldline-go/auth/providers"
)

func TestProviderExtra_RoundTripper(t *testing.T) {
	serverToken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// parse basic auth
		username, password, ok := r.BasicAuth()
		if !ok || (username != "test" && password != "test-secret") {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Forbidden"))

			return
		}

		r.ParseForm()
		if r.Form.Get("grant_type") != "client_credentials" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Bad Request"))

			return
		}

		// r.Header.Get("Authorization")
		value := map[string]string{
			"access_token":  "test-token",
			"token_type":    "bearer",
			"expires_in":    "3600",
			"refresh_token": "test-refresh-token",
		}

		byteV, err := json.Marshal(value)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal Server Error"))

			return
		}

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(byteV)
	}))

	defer serverToken.Close()

	serverDestination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenHeader := r.Header.Get("Authorization")

		if tokenHeader != "Bearer test-token" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Forbidden"))

			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome!"))
	}))

	defer serverDestination.Close()

	authService := Provider{
		Keycloak: &providers.KeyCloak{
			TokenURL:     serverToken.URL,
			ClientID:     "test",
			ClientSecret: "test-secret",
		},
	}

	p := authService.ActiveProvider()

	client := &http.Client{}

	// wrap tansport with auth
	got, err := p.NewOauth2Shared(context.Background())
	// got, err := p.RoundTripper(context.Background(), http.DefaultTransport)
	if err != nil {
		t.Fatalf("ProviderExtra.RoundTripper() error = %v", err)
	}

	roundTripper, err := got.RoundTripper(nil, http.DefaultTransport)
	if err != nil {
		t.Fatalf("got.RoundTripper() error = %v", err)
	}

	client.Transport = roundTripper

	req, err := http.NewRequest("GET", serverDestination.URL, nil)
	if err != nil {
		t.Fatalf("http.NewRequest error = %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do error = %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Status code = %v, want %v", resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll error = %v", err)
	}

	defer resp.Body.Close()

	if string(body) != "Welcome!" {
		t.Fatalf("Body = %v, want %v", string(body), "Welcome!")
	}
}
