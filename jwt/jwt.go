package jwt

import (
	"crypto/md5"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// New function get secret key and options and return a new JWT instance.
//
// Default signing method is jwt.SigningMethodHS256.
//
// Default expiration function is time.Now().Add(time.Hour).Unix().
func New(secret []byte, opts ...Option) *JWT {
	o := option{
		method: jwt.SigningMethodHS256,
		expFunc: func() int64 {
			return time.Now().Add(time.Hour).Unix()
		},
	}

	for _, opt := range opts {
		opt(&o)
	}

	if o.kid == "" {
		// generate kid
		md5Sum := md5.Sum(secret[len(secret)/2:]) //nolint:gosec // not using for security
		o.kid = fmt.Sprintf("%x", md5Sum)
	}

	return &JWT{
		secret:  secret,
		method:  o.method,
		expFunc: o.expFunc,
		kid:     o.kid,
	}
}

type JWT struct {
	secret  []byte
	method  jwt.SigningMethod
	expFunc func() int64
	kid     string
}

func (t *JWT) ExpFunc() int64 {
	return t.expFunc()
}

// Generate function get custom values and add 'exp' as expires at with expDate argument with unix format.
func (t *JWT) Generate(mapClaims map[string]interface{}, expDate int64) (string, error) {
	claims := jwt.MapClaims{}
	for k := range mapClaims {
		claims[k] = mapClaims[k]
	}

	claims["exp"] = expDate

	token := jwt.NewWithClaims(t.method, claims)
	if t.kid != "" {
		token.Header["kid"] = t.kid
	}

	tokenString, err := token.SignedString(t.secret)
	if err != nil {
		err = fmt.Errorf("cannot sign: %w", err)
	}

	return tokenString, err
}

// Validate is validating and getting claims.
func (t *JWT) Validate(tokenStr string) (map[string]interface{}, error) {
	token, err := jwt.Parse(
		tokenStr,
		func(token *jwt.Token) (interface{}, error) {
			return t.secret, nil
		},
		jwt.WithValidMethods([]string{t.method.Alg()}),
	)
	if err != nil {
		return nil, fmt.Errorf("token validate: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token: %w", err)
}

// Renew token with not changing claims.
func (t *JWT) Renew(tokenStr string, expDate int64) (string, error) {
	claims, err := t.Validate(tokenStr)
	if err != nil {
		return "", fmt.Errorf("renew: %w", err)
	}

	return t.Generate(claims, expDate)
}
