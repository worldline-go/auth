package request

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// DefaultAuth is a default Auth struct with http.DefaultClient.
var DefaultAuth = &Auth{
	Client: http.DefaultClient,
}

// Auth is a struct to handle flow of OAuth2.
type Auth struct {
	// Client is a http client to use. If nil, http.DefaultClient will be used.
	Client *http.Client
}

type AuthRequestConfig struct {
	TokenURL string
	ClientID string
	// ClientSecret is optional
	ClientSecret string
	// AuthHeaderStyle is optional. If not set, AuthHeaderStyleBasic will be used.
	AuthHeaderStyle AuthHeaderStyle
	// Scopes for refresh and password flow.
	Scopes []string
}

func (a *Auth) AuthRequest(ctx context.Context, uValues url.Values, cfg AuthRequestConfig) ([]byte, error) {
	encodedData := uValues.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(encodedData))
	if err != nil {
		return nil, err
	}

	// set if style is params
	AuthParams(cfg.ClientID, cfg.ClientSecret, req, cfg.AuthHeaderStyle)
	AuthHeader(req, cfg.ClientID, cfg.ClientSecret, cfg.AuthHeaderStyle)

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("accept", "application/json")

	return a.RawRequest(req)
}

func (a *Auth) RawRequest(req *http.Request) ([]byte, error) {
	client := a.Client
	if client == nil {
		client = http.DefaultClient
	}

	return RawRequest(req, client)
}

func RawRequest(req *http.Request, client *http.Client) ([]byte, error) {
	r, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	// 1MB limit
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	r.Body.Close()

	if code := r.StatusCode; code < 200 || code > 299 {
		return nil, fmt.Errorf(string(body))
	}

	return body, nil
}
