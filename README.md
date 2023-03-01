# Auth

Authenticating and authorizing client/server applications.

## Usage

```sh
go get github.com/worldline-go/auth
```

Check http example: [example/http](example/http)

### Client

Client is usefull to send request with oauth2 token.

First set a provider.

```go
var providerClient = auth.Provider{
	Keycloak: &providers.KeyCloak{
		ClientID:     "test",
		ClientSecret: "GbkxWi8ZBJvMv2Wsh03JbX183xKAPrEs",
        // Keycloak server url
		BaseURL:      "http://localhost:8080",
		Realm:        "finops",
        // Scopes is optional
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
	},
}
```

Then when you create a http.Client you can use the oauth2 transport.

```go
client := &http.Client{
    Transport: providerClient.RoundTripperMust(ctx, http.DefaultTransport),
}
```

Now you can make request with this client.

### Server

Check the token in the request. Just need to url of keycloak server and the realm.

```go
var providerServer = auth.Provider{
	Keycloak: &providers.KeyCloak{
        // Keycloak server url
		BaseURL: "http://localhost:8080",
		Realm:   "finops",
	},
}
```

Then you can check the token in the request.

This is the http based, very simple function but check the our [echo middleware](middlewares/authecho/README.md) to much more advanced operations.

```go
checkFunc, closeRefresh, err := providerServer.Parser(ctx)
if err != nil {
    return fmt.Errorf("creating parser: %w", err)
}
defer closeRefresh()

// Check the token in the request
claimsValue := claims.Custom{}
token, err := checkFunc(tokenToCheck, &claimsValue)
if err != nil {
    return fmt.Errorf("token 👎: %w", err)
}
```

## Redirection Flow

When enabled redirection in the middleware, the user will be redirected to the oauth2 login page.

This is not a standard flow and we can change update it any time.

![Redirection Flow](docs/redirection-flow.svg)

## Development

<details><summary>Keycloak</summary>

Run keycloak in docker

```sh
make keycloak
```

Open http://localhost:8080 and login with admin/admin.

Create a new realm called `finops` and add a new client called `test`.  
Choice client type `openid-connect`.
Enable `Client Authentication` and `Authorization Enabled`.

We connect with oauth2 transport with our client id and secret. In server side we use the public key to verify the token.

Public key id find in the realms key settings.

</details>
