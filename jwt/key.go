package jwt

import "github.com/MicahParks/keyfunc/v2"

// GivenKey useful for mixing other keys in jwks function.
//
//	jwks, err := authProvider.JWTKeyFunc(auth.WithContext(ctx), auth.WithGivenKeys(
//		serverJWT.GivenKey(),
//	))
func (t *JWT) GivenKey() map[string]keyfunc.GivenKey {
	key := keyfunc.NewGivenCustom(
		t.secret,
		keyfunc.GivenKeyOptions{
			Algorithm: t.method.Alg(),
		},
	)

	return map[string]keyfunc.GivenKey{
		t.kid: key,
	}
}
