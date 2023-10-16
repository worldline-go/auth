package models

import "github.com/golang-jwt/jwt/v5"

type InfKeyFunc interface {
	Keyfunc(token *jwt.Token) (interface{}, error)
}

type InfKeyFuncParser interface {
	InfKeyFunc
	ParseWithClaims(tokenString string, claims jwt.Claims) (*jwt.Token, error)
}
