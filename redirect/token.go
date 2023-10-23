package redirect

import (
	"context"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/rs/zerolog/log"
	"github.com/worldline-go/auth/request"
	"github.com/worldline-go/auth/store"
)

// RefreshToken refreshes the access token and set the cookie.
func RefreshToken(ctx context.Context, r *http.Request, w http.ResponseWriter, refreshToken, cookieName string, oldCookieValue string, redirect *Setting, sessionStore *sessions.FilesystemStore) (*store.Token, error) {
	body, err := request.DefaultAuth.RefreshToken(ctx, request.RefreshTokenConfig{
		RefreshToken: refreshToken,
		AuthRequestConfig: request.AuthRequestConfig{
			ClientID:     redirect.ClientID,
			ClientSecret: redirect.ClientSecret,
			TokenURL:     redirect.TokenURL,
			Scopes:       redirect.Scopes,
		},
	})
	if err != nil {
		return nil, err
	}

	// parse body to cookie
	cookieParsed, err := store.Parse(string(body))
	if err != nil {
		return nil, err
	}

	if redirect.Information.Cookie.Name != "" {
		if err := SaveInfo(r, w, cookieParsed.AccessToken, &redirect.Information); err != nil {
			log.Debug().Err(err).Msgf("failed SaveInfo: %v", err)
		}
	}

	if redirect.UseSession {
		if _, err := store.SetSessionB64(r, w, body, cookieName, "cookie", sessionStore); err != nil {
			log.Debug().Err(err).Msg("error save session")
		}

		return cookieParsed, nil
	}

	// set the cookie
	store.SetCookieB64(w, body, cookieName, redirect.MapConfigCookie())

	return cookieParsed, nil
}

// CodeToken get token and set the cookie/session.
func CodeToken(ctx context.Context, r *http.Request, w http.ResponseWriter, code, cookieName string, redirect *Setting, sessionStore *sessions.FilesystemStore) error {
	redirectURI, err := URI(r.Clone(ctx), redirect.Callback, redirect.BaseURL, redirect.Schema)
	if err != nil {
		return err
	}

	body, err := request.DefaultAuth.AuthorizationCode(ctx, request.AuthorizationCodeConfig{
		Code:        code,
		RedirectURL: redirectURI,
		AuthRequestConfig: request.AuthRequestConfig{
			ClientID:     redirect.ClientID,
			ClientSecret: redirect.ClientSecret,
			TokenURL:     redirect.TokenURL,
			Scopes:       redirect.Scopes,
		},
	})
	if err != nil {
		return err
	}

	cookieParsed, err := store.Parse(string(body))
	if err != nil {
		return err
	}

	if redirect.Information.Cookie.Name != "" {
		if err := SaveInfo(r, w, cookieParsed.AccessToken, &redirect.Information); err != nil {
			log.Debug().Err(err).Msgf("failed SaveInfo: %v", err)
		}
	}

	if redirect.UseSession {
		if _, err := store.SetSessionB64(r, w, body, cookieName, "cookie", sessionStore); err != nil {
			return err
		}

		return nil
	}

	// set the cookie
	store.SetCookieB64(w, body, cookieName, redirect.MapConfigCookie())

	return nil
}
