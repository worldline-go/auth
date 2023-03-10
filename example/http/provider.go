package main

import (
	"github.com/worldline-go/auth"
	"github.com/worldline-go/auth/providers"
)

var providerServer = auth.Provider{
	Keycloak: &providers.KeyCloak{
		BaseURL: "http://localhost:8080",
		Realm:   "master",
	},
}

var providerClient = auth.Provider{
	Keycloak: &providers.KeyCloak{
		ClientID:     "test",
		ClientSecret: "GbkxWi8ZBJvMv2Wsh03JbX183xKAPrEs",
		BaseURL:      "http://localhost:8080",
		Realm:        "master",
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
	},
}
