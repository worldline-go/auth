package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var defaultParser = jwt.NewParser()

// NewJWT function get secret key and options and return a new JWT instance.
//
// Default expiration function is time.Now().Add(time.Hour).Unix().
func NewJWT(opts ...OptionJWT) (*JWT, error) {
	o := optionJWT{
		expFunc: func() int64 {
			return time.Now().Add(time.Hour).Unix()
		},
	}

	for _, opt := range opts {
		opt(&o)
	}

	if o.kid == "" {
		return nil, fmt.Errorf("kid is required")
	}

	if o.method == nil {
		return nil, fmt.Errorf("method is required")
	}

	var secret interface{}
	var public interface{}
	switch o.method.(type) {
	case *jwt.SigningMethodHMAC:
		secret = o.secretByte
		public = o.secretByte
	case *jwt.SigningMethodRSAPSS:
		secret = o.secretRSAPrivate
		if o.secretRSAPublic != nil {
			public = o.secretRSAPublic
		} else {
			public = o.secretRSAPrivate.Public()
		}
	case *jwt.SigningMethodRSA:
		secret = o.secretRSAPrivate
		if o.secretRSAPublic != nil {
			public = o.secretRSAPublic
		} else {
			public = o.secretRSAPrivate.Public()
		}
	case *jwt.SigningMethodECDSA:
		secret = o.secretECDSAPrivate
		if o.secretECDSAPublic != nil {
			public = o.secretECDSAPublic
		} else {
			public = o.secretECDSAPrivate.Public()
		}
	default:
		return nil, fmt.Errorf("unsupported method")
	}

	if secret == nil || public == nil {
		return nil, fmt.Errorf("secret and public key is required")
	}

	return &JWT{
		secret:  secret,
		public:  public,
		method:  o.method,
		expFunc: o.expFunc,
		kid:     o.kid,
	}, nil
}

type JWT struct {
	secret  interface{}
	public  interface{}
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

	if expDate > 0 {
		claims["exp"] = expDate
	}

	token := jwt.NewWithClaims(t.method, claims)

	// header part
	if t.kid != "" {
		token.Header["kid"] = t.kid
	}
	if t.method.Alg() != "" {
		token.Header["alg"] = t.method.Alg()
	}

	tokenString, err := token.SignedString(t.secret)
	if err != nil {
		err = fmt.Errorf("cannot sign: %w", err)
	}

	return tokenString, err
}

// Parse is validating and getting claims.
func (t *JWT) Parse(tokenStr string, claims jwt.Claims) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(
		tokenStr,
		claims,
		func(token *jwt.Token) (interface{}, error) {
			return t.public, nil
		},
		jwt.WithValidMethods([]string{t.method.Alg()}),
	)
	if err != nil {
		return nil, fmt.Errorf("token validate: %w", err)
	}

	return token, nil
}

// Renew token with not changing claims.
func (t *JWT) Renew(tokenStr string, expDate int64) (string, error) {
	claims := jwt.MapClaims{}
	if _, err := t.Parse(tokenStr, &claims); err != nil {
		return "", fmt.Errorf("renew: %w", err)
	}

	return t.Generate(claims, expDate)
}

func ParseUnverified(tokenString string, claims jwt.Claims) (*jwt.Token, []string, error) {
	return defaultParser.ParseUnverified(tokenString, claims)
}
