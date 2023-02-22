package authecho

import (
	"encoding/base64"
	"encoding/json"

	"github.com/labstack/echo/v4"
)

type Cookie struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

func NewCookie(v string, b64 bool) (Cookie, error) {
	cookieRecord := Cookie{}
	vByte := []byte(v)

	if b64 {
		var err error
		vByte, err = base64.StdEncoding.DecodeString(v)
		if err != nil {
			return cookieRecord, err
		}
	}

	// parse cookie
	if err := json.Unmarshal(vByte, &cookieRecord); err != nil {
		return cookieRecord, err
	}

	return cookieRecord, nil
}

func AddAuthorizationHeader(c echo.Context, token string) error {
	c.Request().Header.Add("Authorization", "Bearer "+token)

	return nil
}
