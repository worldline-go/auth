package docs

import "github.com/swaggo/swag"

func SetVersion() {
	if spec, ok := swag.GetSwagger("swagger").(*swag.Spec); ok {
		spec.Title = "auth-test"
		spec.Version = "v0.0.0"
	}
}
