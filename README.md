# Auth

Authenticating and authorizing client/server applications.

## Usage

```sh
go get github.com/worldline-go/auth
```

Check http example: [example/http](example/http)

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
