package auth

import (
	"crypto/md5"
	"fmt"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/worldline-go/auth/models"
)

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

func (t *JWT) Jwks() models.InfKeyFunc {
	return keyfunc.NewGiven(t.GivenKey())
}

func GenerateKeyID(random []byte) string {
	md5Sum := md5.Sum(random[len(random)/2:]) //nolint:gosec // not using for security

	return fmt.Sprintf("%x", md5Sum)
}
