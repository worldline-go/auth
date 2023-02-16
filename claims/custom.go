package claims

import (
	"encoding/json"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

type Custom struct {
	// AuthorizedParty tells which client was used to create token.
	AuthorizerParty string           `json:"azp,omitempty"`
	User            string           `json:"preferred_username,omitempty"`
	Scope           string           `json:"scope,omitempty"`
	RealmAccess     Roles            `json:"realm_access,omitempty"`
	ResourceAccess  map[string]Roles `json:"resource_access,omitempty"`

	// custom maps for fast lookup
	ScopeSet map[string]struct{} `json:"-"`
	RoleSet  map[string]struct{} `json:"-"`

	jwt.RegisteredClaims
}

func (c *Custom) UnmarshalJSON(b []byte) error {
	type newCustom Custom
	if err := json.Unmarshal(b, (*newCustom)(c)); err != nil {
		return err
	}

	if c.Scope != "" {
		c.ScopeSet = make(map[string]struct{})
		for _, s := range strings.Split(c.Scope, " ") {
			c.ScopeSet[s] = struct{}{}
		}
	}

	if c.RealmAccess.Roles != nil {
		c.RoleSet = make(map[string]struct{})
		for _, r := range c.RealmAccess.Roles {
			c.RoleSet[r] = struct{}{}
		}
	}

	if c.ResourceAccess != nil {
		for _, r := range c.ResourceAccess {
			for _, role := range r.Roles {
				c.RoleSet[role] = struct{}{}
			}
		}
	}

	return nil
}

type Roles struct {
	Roles []string `json:"roles,omitempty"`
}

func (c *Custom) HasRole(role string) bool {
	if _, ok := c.RoleSet[role]; ok {
		return true
	}

	return false
}

func (c *Custom) HasScope(scope string) bool {
	if _, ok := c.ScopeSet[scope]; ok {
		return true
	}

	return false
}
