module github.com/worldline-go/auth/example/http

go 1.19

replace (
	github.com/worldline-go/auth => ../../
	github.com/worldline-go/auth/middlewares/authecho => ../../middlewares/authecho
)

require (
	github.com/labstack/echo/v4 v4.10.2
	github.com/rs/zerolog v1.29.1
	github.com/rytsh/liz/shutdown v0.1.0
	github.com/swaggo/echo-swagger v1.3.5
	github.com/swaggo/swag v1.8.12
	github.com/worldline-go/auth v0.5.0
	github.com/worldline-go/auth/middlewares/authecho v0.0.0-00010101000000-000000000000
	github.com/worldline-go/logz v0.3.3
	github.com/worldline-go/logz/logecho v0.1.1
	github.com/worldline-go/utility/swagger v0.1.0
	github.com/ziflex/lecho/v3 v3.5.0
)

require (
	github.com/KyleBanks/depth v1.2.1 // indirect
	github.com/MicahParks/keyfunc v1.9.0 // indirect
	github.com/MicahParks/keyfunc/v2 v2.0.3 // indirect
	github.com/go-openapi/jsonpointer v0.19.6 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/spec v0.20.9 // indirect
	github.com/go-openapi/swag v0.22.3 // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.0.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/gorilla/securecookie v1.1.1 // indirect
	github.com/gorilla/sessions v1.2.1 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/labstack/echo-jwt/v4 v4.2.0 // indirect
	github.com/labstack/gommon v0.4.0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.18 // indirect
	github.com/swaggo/files v0.0.0-20220728132757-551d4a08d97a // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	golang.org/x/crypto v0.9.0 // indirect
	golang.org/x/net v0.10.0 // indirect
	golang.org/x/oauth2 v0.8.0 // indirect
	golang.org/x/sys v0.8.0 // indirect
	golang.org/x/text v0.9.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.org/x/tools v0.9.1 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
