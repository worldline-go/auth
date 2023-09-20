# auth library for echo

This library provides a middleware for echo web-framework to handle authentication.  
Features are auto-redirection to login page, auto-refresh of access token.

There are a few other middlewares in it that can help you to build a complete authentication system.

```sh
import "github.com/worldline-go/auth/pkg/authecho"
```

## Usage

It is working based on the jwks functions. Our auth library already return a jwks key function.

```go
// set a noop value to disable authentication in test mode
noop := strings.EqualFold(os.Getenv("ENV"), "test")
// or you can set the "noop" to value of active auth provider
// providerConfig.Active = "noop"

// jwks part by auth library
provider := providerConfig.ActiveProvider(auth.WithNoop(noop))

// jwks key function
jwks, err := provider.JWTKeyFunc(ctx)
if err != nil {
    return err
}

// close jwks retantion in background
defer jwks.EndBackground()

// echo part

// if we want to use the middleware for all routes
e.Use(authecho.MiddlewareJWT(
    // if your jwks from a noop provider, noop always true
    // authecho.WithNoop(noop),
    authecho.WithKeyFunc(jwks.Keyfunc),
    authecho.WithSkipper(authecho.NewSkipper()),
))

// if we want to use the middleware for some routes
// add this to the parameters of the route
mJWT := authecho.MiddlewareJWT(
    // if your jwks from a noop provider, noop always true
    // authecho.WithNoop(noop),
    authecho.WithKeyFunc(jwks.Keyfunc),
    authecho.WithSkipper(authecho.NewSkipper()),
)

// control based on roles and scopes
// it will check transaction role and email scope, if not exist it will return 403
e.GET("/", func(c echo.Context) error {
    //...
}, authecho.MiddlewareRole(
        // if your jwks from a noop provider, noop always true
        // authecho.WithNoopRole(noop),
        authecho.WithRoles("transaction"),
    ),
    authecho.MiddlewareScope(
        // if your jwks from a noop provider, noop always true
        // authecho.WithNoopRole(noop),
        authecho.WithScopes("email"),
    ),
)
```

## Options

__WithNoop__ return a new noop function, it is useful when you want to disable the middleware for some routes.

This is the same effect to set Active value in config to `noop`.

```go
authecho.WithNoop(noop bool)
```

__WithKeyFunc__ return a new key function, it is required to use the jwks key function.

```go
authecho.WithKeyFunc(fn jwt.Keyfunc)
```

__WithSkipper__ return a new skipper function, it is useful when you want to skip the middleware for some routes.

```go
authecho WithSkipper(skipper middleware.Skipper)

// Example:
// NewSkipper ask for a list of suffexes to skip the middleware
authecho.WithSkipper(authecho.NewSkipper())
```

__WithClaims__ return a new claims function, it is useful when you want to add custom claims to the token.  
We have already a custom claims function for the auth library.  
Don't use it, if you don't know what you are doing.

```go
authecho.WithClaims(newClaims func() jwt.Claims)
```

__WithClaimsHeader__ to add custom claims to the header of the request. Set the header-key for scopes, roles and user.

```go
type ClaimsHeader struct {
	// Scopes is the header name for scopes, default is X-Auth-Scopes.
	Scopes string `cfg:"scopes"`
	// Roles is the header name for roles, default is X-Auth-Roles.
	Roles string `cfg:"roles"`
	// User is the header name for user, default is X-Auth-User.
	User string `cfg:"user"`
	// Custom is the header name for custom claims.
	Custom map[string]string `cfg:"custom"`
}

// Example for custom, it will get key from the token and set it to the header.
custom := map[string]string{
    "X-Auth-Username": "name",
    "X-Auth-Useremail": "email",
}
```

```go
WithClaimsHeader(claimsHeader *ClaimsHeader)
```

__WithRedirect__ to add custom redirect settings.  
Redirect to the login page if the user is not authenticated.  
Checking the Authorization header for the token, if not exist checking the cookie.

Before to authenticate with access_token, we check the refresh_token, default is _10s_ before the access_token expires.

RedirectSetting struct:

```go
// CookieName is the name of the cookie. Default is "auth_" + ClientID.
CookieName string `cfg:"cookie_name"`
// Callback is the callback URI.
Callback string `cfg:"callback"`
// MaxAge for the cookie.
MaxAge int `cfg:"max_age"`
// Path for the cookie.
Path string `cfg:"path"`
// Domain for the cookie.
Domain string `cfg:"domain"`
// BaseURL is the base URL to use for the redirect.
// Default is the request Host with checking the X-Forwarded-Host header.
BaseURL string `cfg:"base_url"`
// Schema is the default schema to use for the redirect if no schema is provided.
// Default is the https schema.
Schema string `cfg:"schema"`
// Secure is the secure flag for the cookie.
Secure bool `cfg:"secure"`

// UseSession is use session instead of cookie.
UseSession bool `cfg:"use_session"`
// SessionKey secret key for session.
SessionKey string `cfg:"session_key"`

// TokenHeader to add token to header.
TokenHeader bool `cfg:"token_header"`
// RefreshToken is use to refresh the token.
RefreshToken bool `cfg:"refresh_token"`

CheckValue string `cfg:"check_value"`
CheckAgent bool   `cfg:"check_agent"`
```

If you not give the RedirectSetting, the middleware will not redirect to the login page.

```go
WithRedirect(redirect *RedirectSetting)
```
