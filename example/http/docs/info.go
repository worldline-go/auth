package docs

import (
	"github.com/worldline-go/auth"
	"github.com/worldline-go/utility/swagger"
)

func Info(version string, provider auth.InfProvider) error {
	return swagger.SetInfo(
		swagger.WithVersion(version),
		swagger.WithCustom(map[string]interface{}{
			"tokenUrl":   provider.GetTokenURL(),
			"authUrl":    provider.GetAuthURL(),
			"refreshUrl": provider.GetTokenURL(),
		}),
	)
}
