package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWT_Generate(t *testing.T) {
	type args struct {
		claims  jwt.MapClaims
		expDate int64
	}
	tests := []struct {
		name            string
		fields          []Option
		args            args
		wantValidateErr bool
		wantErr         bool
	}{
		{
			name:            "empty",
			fields:          []Option{},
			args:            args{},
			wantValidateErr: false,
			wantErr:         true,
		},
		{
			name: "simple false",
			fields: []Option{
				WithSecretByte([]byte("pass1234")),
				WithMethod(jwt.SigningMethodHS256),
			},
			args:            args{},
			wantValidateErr: false,
			wantErr:         false,
		},
		{
			name: "with 1 hour",
			fields: []Option{
				WithSecretByte([]byte("pass1234")),
				WithMethod(jwt.SigningMethodHS256),
			},
			args: args{
				claims:  map[string]interface{}{"info": "hello"},
				expDate: time.Now().Add(time.Hour).Unix(),
			},
			wantValidateErr: false,
			wantErr:         false,
		},
		{
			name: "rsa",
			fields: func() []Option {
				v, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					return nil
				}

				return []Option{
					WithRSAPrivateKey(v),
					WithMethod(jwt.SigningMethodRS256),
				}
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr, err := New(append(tt.fields, WithKID("test"))...)
			if err != nil {
				if tt.wantErr {
					return
				}

				t.Fatalf("JWT.Generate() error = %v", err)
			}

			fmt.Println(tr.kid)
			got, err := tr.Generate(tt.args.claims, tt.args.expDate)
			if (err != nil) != tt.wantErr {
				t.Fatalf("JWT.Generate() error = %v, wantErr %v", err, tt.wantErr)
			}
			fmt.Println(got)
			claims := jwt.MapClaims{}
			_, err = tr.Parse(got, &claims)
			if (err != nil) != tt.wantValidateErr {
				t.Fatalf("JWT.Validate() error = %v, wantValidateErr %v", err, tt.wantValidateErr)
			}

			delete(claims, "exp")
			if len(tt.args.claims) != 0 && !reflect.DeepEqual(tt.args.claims, claims) {
				t.Fatalf("claims %#v, want %#v", claims, tt.args.claims)
			}
		})
	}
}
