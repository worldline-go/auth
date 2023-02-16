package main

import (
	"github.com/worldline-go/auth"
	"github.com/worldline-go/auth/providers"
)

var providerServer = auth.Provider{
	Keycloak: &providers.KeyCloak{
		BaseURL: "http://localhost:8080",
		Realm:   "finops",
	},
}

var providerClient = auth.Provider{
	Keycloak: &providers.KeyCloak{
		ClientID:     "test2",
		ClientSecret: "BGtwMXmnHhxvUfvvk1GnuUUq4pexVbfP",
		BaseURL:      "http://localhost:8080",
		Realm:        "finops",
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
	},
}
