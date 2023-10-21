package docs

import (
	_ "github.com/swaggo/swag"

	"github.com/worldline-go/auth"
	"github.com/worldline-go/swagger"
)

func Info(version string, provider auth.InfProvider) error {
	return swagger.SetInfo(
		swagger.WithVersion(version),
		swagger.WithCustom(map[string]interface{}{
			"tokenUrl": provider.GetTokenURLExternal(),
			"authUrl":  provider.GetAuthURLExternal(),
		}),
	)
}
