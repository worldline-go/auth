package claims

import (
	"encoding/json"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Custom claims based on jwt.RegisteredClaims with additional Roles and Scope unmarshal.
type Custom struct {
	// AuthorizedParty tells which client was used to create token.
	AuthorizerParty string           `json:"azp,omitempty"`
	User            string           `json:"preferred_username,omitempty"`
	Scope           string           `json:"scope,omitempty"`
	RealmAccess     Roles            `json:"realm_access,omitempty"`
	ResourceAccess  map[string]Roles `json:"resource_access,omitempty"`
	// Roles usable for custom application.
	Roles []string `json:"roles,omitempty"`

	// custom maps for fast lookup

	ScopeSet map[string]struct{} `json:"-"`
	RoleSet  map[string]struct{} `json:"-"`

	// Map claims
	Map map[string]interface{} `json:"-"`

	jwt.RegisteredClaims
}

type Roles struct {
	Roles []string `json:"roles,omitempty"`
}

func (c *Custom) UnmarshalJSON(b []byte) error {
	type newCustom Custom
	if err := json.Unmarshal(b, (*newCustom)(c)); err != nil {
		return err
	}

	if err := json.Unmarshal(b, &c.Map); err != nil {
		return err
	}
	c.ScopeSet = make(map[string]struct{})
	c.RoleSet = make(map[string]struct{})

	// set scope
	if c.Scope != "" {
		for _, s := range strings.Fields(c.Scope) {
			c.ScopeSet[s] = struct{}{}
		}
	}

	// set roles
	if c.RealmAccess.Roles != nil {
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
	for _, role := range c.Roles {
		c.RoleSet[role] = struct{}{}
	}

	return nil
}

func (c *Custom) HasRole(role string) bool {
	if role == "" {
		return true
	}

	if _, ok := c.RoleSet[role]; ok {
		return true
	}

	return false
}

func (c *Custom) HasScope(scope string) bool {
	if scope == "" {
		return true
	}

	if _, ok := c.ScopeSet[scope]; ok {
		return true
	}

	return false
}
