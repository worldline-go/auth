package redirect

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/worldline-go/auth/claims"
	"github.com/worldline-go/auth/store"
)

// Info is use to store some information about token.
type Info struct {
	Roles  []string               `json:"roles,omitempty"`
	Scopes []string               `json:"scopes,omitempty"`
	Map    map[string]interface{} `json:"map,omitempty"`
	Custom map[string]interface{} `json:"custom,omitempty"`
}

func SaveInfo(r *http.Request, w http.ResponseWriter, accessToken string, information *Information) error {
	info := Info{}

	claim := claims.Custom{}
	_, _, err := jwt.NewParser().ParseUnverified(accessToken, &claim)
	if err != nil {
		return err
	}

	if information.Cookie.Roles {
		info.Roles = make([]string, 0, len(claim.RoleSet))
		for key := range claim.RoleSet {
			info.Roles = append(info.Roles, key)
		}
	}

	if information.Cookie.Scopes {
		info.Scopes = strings.Fields(claim.Scope)
	}

	if len(information.Cookie.Map) > 0 {
		info.Map = make(map[string]interface{}, len(information.Cookie.Map))
		for _, v := range information.Cookie.Map {
			info.Map[v] = claim.Map[v]
		}
	}

	info.Custom = information.Cookie.Custom

	v, err := json.Marshal(info)
	if err != nil {
		return err
	}

	store.SetCookie(w, string(v), information.Cookie.Name, information.Cookie.MapConfigCookie())

	return nil
}
