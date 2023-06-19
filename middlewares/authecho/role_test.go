package authecho

import (
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/worldline-go/auth/claims"
)

type HandlerFunc struct {
	Count int
}

func (h *HandlerFunc) Fn(c echo.Context) error {
	h.Count++

	return nil
}

func TestMiddlewareRole(t *testing.T) {
	type args struct {
		opts []OptionRole
	}
	tests := []struct {
		name    string
		args    args
		handler HandlerFunc
		claims  *claims.Custom
		want    int
	}{
		{
			name: "positive role check",
			args: args{
				opts: []OptionRole{
					WithRoles("admin", "account"),
				},
			},
			handler: HandlerFunc{},
			claims: &claims.Custom{
				RoleSet: map[string]struct{}{
					"admin": {},
				},
			},
			want: 1,
		},
		{
			name: "empty role map",
			args: args{
				opts: []OptionRole{
					WithRoles("", ""),
				},
			},
			handler: HandlerFunc{},
			claims: &claims.Custom{
				RoleSet: map[string]struct{}{
					"admin":       {},
					"account":     {},
					"transaction": {},
				},
			},
			want: 1,
		},
		{
			name: "empty role map empty",
			args: args{
				opts: []OptionRole{
					WithRoles(),
				},
			},
			handler: HandlerFunc{},
			claims: &claims.Custom{
				RoleSet: map[string]struct{}{
					"admin": {},
				},
			},
			want: 1,
		},
		{
			name: "role not in role map",
			args: args{
				opts: []OptionRole{
					WithRoles("admin"),
				},
			},
			handler: HandlerFunc{},
			claims: &claims.Custom{
				RoleSet: map[string]struct{}{
					"account":     {},
					"transaction": {},
				},
			},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware := MiddlewareRole(tt.args.opts...)
			fn := middleware(tt.handler.Fn)

			e := echo.New()
			echoCtx := e.NewContext(nil, nil)
			echoCtx.Set("claims", tt.claims)

			_ = fn(echoCtx)

			if tt.handler.Count != tt.want {
				t.Errorf("MiddlewareRole() = %v, want %v", tt.handler.Count, tt.want)
			}
		})
	}
}
