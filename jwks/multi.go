package jwks

import (
	"errors"
	"fmt"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/worldline-go/auth/models"
)

var ErrKIDNotFound = keyfunc.ErrKIDNotFound

type InfProvider interface {
	GetCertURL() string
	IsNoop() bool
}

type KeyFuncMulti struct {
	givenJwks models.InfKeyFunc
	multiJWKS *keyfunc.MultipleJWKS
}

func (k *KeyFuncMulti) KeySelectorFirst(multiJWKS *keyfunc.MultipleJWKS, token *jwt.Token) (interface{}, error) {
	if k.givenJwks != nil {
		key, err := k.givenJwks.Keyfunc(token)
		if err == nil {
			return key, nil
		}
		if !errors.Is(err, ErrKIDNotFound) {
			return nil, err
		}
	}

	return keyfunc.KeySelectorFirst(multiJWKS, token)
}

func (k *KeyFuncMulti) Keyfunc(token *jwt.Token) (interface{}, error) {
	return k.multiJWKS.Keyfunc(token)
}

// MultiJWTKeyFunc returns a jwt.Keyfunc with multiple keyfunc.
//
// Doesn't support introspect and noops, it will ignore them.
func MultiJWTKeyFunc(providers []InfProvider, opts ...OptionJWK) (models.InfKeyFunc, error) {
	opt := GetOptionJWK(opts...)
	keyFuncOpt := MapOptionKeyfunc(opt)

	multi := map[string]keyfunc.Options{}
	for _, provider := range providers {
		if provider.IsNoop() || opt.Introspect {
			continue
		}

		certURL := provider.GetCertURL()
		if certURL == "" {
			return nil, fmt.Errorf("no cert URL")
		}

		multi[certURL] = keyFuncOpt
	}

	if len(multi) == 0 && opt.KeyFunc != nil {
		return &KeyFuncParser{
			KeyFunc: opt.KeyFunc.Keyfunc,
		}, nil
	}

	multiKeyFunc := &KeyFuncMulti{
		givenJwks: opt.KeyFunc,
	}
	jwks, err := keyfunc.GetMultiple(multi, keyfunc.MultipleOptions{
		KeySelector: multiKeyFunc.KeySelectorFirst,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to getMultiple: %w", err)
	}

	multiKeyFunc.multiJWKS = jwks

	return &KeyFuncParser{
		KeyFunc: multiKeyFunc.Keyfunc,
	}, nil
}
