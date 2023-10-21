# Logout on oauth2

For details check this link https://openid.net/specs/openid-connect-rpinitiated-1_0.html

Example keycloak logout button

```html
<li>
<a href="https://keycloak.example.com/auth/realms/master/protocol/openid-connect/logout?id_token_hint=<id_token>&post_logout_redirect_uri=https%3A%2F%2Fmywebsite.com%2Flogin&client_id=my-client-id">Logout</a>
</li>
```

Giving parameters to the logout url, use URL encoding:

```
id_token_hint: <value>
post_logout_redirect_uri: https://mywebsite.com/login
client_id: my-client-id
```

__id_token_hint__ is important and it is the `sid` in the token we see.

Frontend UI shouldn't be know about the our token so we should use another middleware to handle our logout process.

Check [Turna](worldline-go.github.io/turna/) to make it easier.
