package providers

import (
	"testing"

	"github.com/go-test/deep"
)

func TestKeyCloak_GetAuthURL(t *testing.T) {
	type want struct {
		TokenURL         string
		TokenURLExternal string
		AuthURL          string
		AuthURLExternal  string
		CertURL          string
		ClientID         string
		ClientSecret     string
		IntrospectURL    string
		Scopes           []string
	}
	type fields struct {
		ClientID         string
		ClientSecret     string
		Scopes           []string
		CertURL          string
		IntrospectURL    string
		AuthURL          string
		AuthURLExternal  string
		TokenURL         string
		TokenURLExternal string
		BaseURL          string
		BaseURLExternal  string
		Realm            string
	}
	tests := []struct {
		name   string
		fields fields
		want   want
	}{
		{
			name: "test basic",
			fields: fields{
				BaseURL:         "https://keycloak/auth",
				BaseURLExternal: "https://keycloak.example.com/auth",
				Realm:           "test",
			},
			want: want{
				TokenURL:         "https://keycloak/auth/realms/test/protocol/openid-connect/token",
				TokenURLExternal: "https://keycloak.example.com/auth/realms/test/protocol/openid-connect/token",
				AuthURL:          "https://keycloak/auth/realms/test/protocol/openid-connect/auth",
				AuthURLExternal:  "https://keycloak.example.com/auth/realms/test/protocol/openid-connect/auth",
				CertURL:          "https://keycloak/auth/realms/test/protocol/openid-connect/certs",
				ClientID:         "",
				ClientSecret:     "",
				IntrospectURL:    "",
				Scopes:           nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &KeyCloak{
				ClientID:         tt.fields.ClientID,
				ClientSecret:     tt.fields.ClientSecret,
				Scopes:           tt.fields.Scopes,
				CertURL:          tt.fields.CertURL,
				IntrospectURL:    tt.fields.IntrospectURL,
				AuthURL:          tt.fields.AuthURL,
				AuthURLExternal:  tt.fields.AuthURLExternal,
				TokenURL:         tt.fields.TokenURL,
				TokenURLExternal: tt.fields.TokenURLExternal,
				BaseURL:          tt.fields.BaseURL,
				BaseURLExternal:  tt.fields.BaseURLExternal,
				Realm:            tt.fields.Realm,
			}
			if got := p.GetAuthURL(); got != tt.want.AuthURL {
				t.Errorf("KeyCloak.GetAuthURL() = %v, want %v", got, tt.want.AuthURL)
			}
			if got := p.GetAuthURLExternal(); got != tt.want.AuthURLExternal {
				t.Errorf("KeyCloak.GetAuthURLExternal() = %v, want %v", got, tt.want.AuthURLExternal)
			}
			if got := p.GetTokenURL(); got != tt.want.TokenURL {
				t.Errorf("KeyCloak.GetTokenURL() = %v, want %v", got, tt.want.TokenURL)
			}
			if got := p.GetTokenURLExternal(); got != tt.want.TokenURLExternal {
				t.Errorf("KeyCloak.GetTokenURLExternal() = %v, want %v", got, tt.want.TokenURLExternal)
			}
			if got := p.GetCertURL(); got != tt.want.CertURL {
				t.Errorf("KeyCloak.GetCertURL() = %v, want %v", got, tt.want.CertURL)
			}
			if got := p.GetClientID(); got != tt.want.ClientID {
				t.Errorf("KeyCloak.GetClientID() = %v, want %v", got, tt.want.ClientID)
			}
			if got := p.GetClientSecret(); got != tt.want.ClientSecret {
				t.Errorf("KeyCloak.GetClientSecret() = %v, want %v", got, tt.want.ClientSecret)
			}
			if got := p.GetIntrospectURL(); got != tt.want.IntrospectURL {
				t.Errorf("KeyCloak.GetIntrospectURL() = %v, want %v", got, tt.want.IntrospectURL)
			}
			if diff := deep.Equal(p.GetScopes(), tt.want.Scopes); diff != nil {
				t.Errorf("KeyCloak.GetScopes() = %v", diff)
			}
		})
	}
}
