package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/worldline-go/auth/models"
	"github.com/worldline-go/auth/request"
)

var IntrospectKey = "introspect"

type RestIntrospect struct {
	Active bool `json:"active"`
}

type IntrospectJWTKey struct {
	URL          string
	ClientID     string
	ClientSecret string

	Client *http.Client
	Ctx    context.Context
}

func (IntrospectJWTKey) Keyfunc(token *jwt.Token) (interface{}, error) {
	return IntrospectKey, nil
}

func (i IntrospectJWTKey) ParseWithClaims(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
	if i.URL == "" {
		return nil, fmt.Errorf("no introspect URL")
	}

	if err := i.CheckIntrospect(tokenString); err != nil {
		return nil, err
	}

	token, _, err := jwt.NewParser().ParseUnverified(tokenString, claims)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (i IntrospectJWTKey) CheckIntrospect(token string) error {
	client := i.Client
	if client == nil {
		client = http.DefaultClient
	}

	uValues := url.Values{
		"token":           {token},
		"token_type_hint": {"access_token"},
	}

	encodedData := uValues.Encode()

	req, err := http.NewRequestWithContext(i.Ctx, http.MethodPost, i.URL, strings.NewReader(encodedData))
	if err != nil {
		return err
	}

	if i.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(i.ClientID), url.QueryEscape(i.ClientSecret))
	} else {
		query := req.URL.Query()
		query.Add("client_id", i.ClientID)

		req.URL.RawQuery = query.Encode()
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("accept", "application/json")

	v, err := request.RawRequest(req, client)
	if err != nil {
		return err
	}

	var restIntrospect RestIntrospect
	if err := json.Unmarshal(v, &restIntrospect); err != nil {
		return err
	}

	if !restIntrospect.Active {
		return models.ErrTokenInvalid
	}

	return nil
}
