package claims

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/golang-jwt/jwt/v5"
)

func TestCustom_UnmarshalJSON(t *testing.T) {
	type args struct {
		b []byte
	}
	tests := []struct {
		name    string
		custom  Custom
		args    args
		wantErr bool
	}{
		{
			name: "test",
			custom: Custom{
				AuthorizerParty: "test",
				User:            "service-account-test",
				Scope:           "email profile",
				RealmAccess: Roles{
					Roles: []string{
						"offline_access",
						"default-roles-finops",
						"uma_authorization",
					},
				},
				ResourceAccess: map[string]Roles{
					"test": {
						Roles: []string{
							"uma_protection",
						},
					},
					"account": {
						Roles: []string{
							"manage-account",
							"manage-account-links",
							"view-profile",
						},
					},
				},
				Roles: []string{"admin-x"},
				ScopeSet: map[string]struct{}{
					"email":   {},
					"profile": {},
				},
				RoleSet: map[string]struct{}{
					"offline_access":       {},
					"default-roles-finops": {},
					"uma_authorization":    {},
					"uma_protection":       {},
					"manage-account":       {},
					"manage-account-links": {},
					"view-profile":         {},
					"admin-x":              {},
				},
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Unix(1671493549, 0)),
					IssuedAt:  jwt.NewNumericDate(time.Unix(1671493249, 0)),
					ID:        "23587604-0d18-472e-80ee-124b179af77f",
					Issuer:    "http://localhost:8080/realms/finops",
					Audience:  jwt.ClaimStrings{"account"},
					Subject:   "49e36c8e-1372-4191-81e4-9516fb439982",
				},
				Map: map[string]interface{}{
					"exp": float64(1671493549),
					"iat": float64(1671493249),
					"jti": "23587604-0d18-472e-80ee-124b179af77f",
					"iss": "http://localhost:8080/realms/finops",
					"aud": "account",
					"sub": "49e36c8e-1372-4191-81e4-9516fb439982",
					"typ": "Bearer",
					"azp": "test",
					"acr": "1",
					"realm_access": map[string]interface{}{
						"roles": []interface{}{
							"offline_access",
							"default-roles-finops",
							"uma_authorization",
						},
					},
					"resource_access": map[string]interface{}{
						"test": map[string]interface{}{
							"roles": []interface{}{
								"uma_protection",
							},
						},
						"account": map[string]interface{}{
							"roles": []interface{}{
								"manage-account",
								"manage-account-links",
								"view-profile",
							},
						},
					},
					"roles":              []interface{}{"admin-x"},
					"scope":              "email profile",
					"clientHost":         "172.17.0.1",
					"email_verified":     false,
					"clientId":           "test",
					"preferred_username": "service-account-test",
					"clientAddress":      "172.17.0.1",
				},
			},
			args: args{
				b: []byte(`{
					"exp": 1671493549,
					"iat": 1671493249,
					"jti": "23587604-0d18-472e-80ee-124b179af77f",
					"iss": "http://localhost:8080/realms/finops",
					"aud": "account",
					"sub": "49e36c8e-1372-4191-81e4-9516fb439982",
					"typ": "Bearer",
					"azp": "test",
					"acr": "1",
					"realm_access": {
						"roles": [
							"offline_access",
							"default-roles-finops",
							"uma_authorization"
						]
					},
					"resource_access": {
						"test": {
							"roles": [
								"uma_protection"
							]
						},
						"account": {
							"roles": [
								"manage-account",
								"manage-account-links",
								"view-profile"
							]
						}
					},
					"roles": ["admin-x"],
					"scope": "email profile",
					"clientHost": "172.17.0.1",
					"email_verified": false,
					"clientId": "test",
					"preferred_username": "service-account-test",
					"clientAddress": "172.17.0.1"
				}`),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := Custom{}
			if err := json.Unmarshal(tt.args.b, &v); (err != nil) != tt.wantErr {
				t.Errorf("Custom.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}

			if diff := deep.Equal(v, tt.custom); diff != nil {
				t.Errorf("Custom.UnmarshalJSON() = %v", diff)
			}
		})
	}
}
