package claims

import "github.com/golang-jwt/jwt/v4"

type Custom struct {
	// AuthorizedParty tells which client was used to create token.
	AuthorizerParty string           `json:"azp,omitempty"`
	User            string           `json:"preferred_username,omitempty"`
	Scope           string           `json:"scope,omitempty"`
	RealmAccess     Roles            `json:"realm_access,omitempty"`
	ResourceAccess  map[string]Roles `json:"resource_access,omitempty"`

	jwt.StandardClaims
}

type Roles struct {
	Roles []string `json:"roles,omitempty"`
}

func (r Roles) HasRole(role string) bool {
	for _, r := range r.Roles {
		if r == role {
			return true
		}
	}

	return false
}

func (c *Custom) HasRole(role string) bool {
	if c.RealmAccess.HasRole(role) {
		return true
	}

	if c.ResourceAccess["account"].HasRole(role) {
		return true
	}

	if c.ResourceAccess[c.AuthorizerParty].HasRole(role) {
		return true
	}

	return false
}
