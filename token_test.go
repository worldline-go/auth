package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestIsRefreshNeed(t *testing.T) {
	type args struct {
		token *jwt.Token
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "expire nearly",
			args: args{
				token: jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second * 5)),
				}),
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "expired",
			args: args{
				token: jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Second)),
				}),
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "more than expire duration",
			args: args{
				token: jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(12 * time.Second)),
				}),
			},
			want:    false,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Errorf("GenerateKey() error = %v", err)
				return
			}

			accessToken, err := tt.args.token.SignedString(key)
			if err != nil {
				t.Errorf("SignedString() error = %v", err)
				return
			}

			got, err := IsRefreshNeed(accessToken)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsRefreshNeed() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("IsRefreshNeed() = %v, want %v", got, tt.want)
			}
		})
	}
}
