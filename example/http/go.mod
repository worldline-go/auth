module github.com/worldline-go/auth/example/http

go 1.17

replace github.com/worldline-go/auth => ../../

replace github.com/worldline-go/auth/middlewares/authecho => ../../middlewares/authecho

require (
	github.com/labstack/echo/v4 v4.10.0
	github.com/rs/zerolog v1.29.0
	github.com/worldline-go/auth v0.3.0
	github.com/worldline-go/auth/middlewares/authecho v0.3.2
	github.com/worldline-go/logz v0.3.1
	github.com/worldline-go/logz/logecho v0.1.0
	github.com/ziflex/lecho/v3 v3.3.0
)

require (
	github.com/MicahParks/keyfunc v1.7.0 // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/golang-jwt/jwt/v4 v4.4.3 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/labstack/echo-jwt/v4 v4.1.0 // indirect
	github.com/labstack/gommon v0.4.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.16 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	golang.org/x/crypto v0.4.0 // indirect
	golang.org/x/net v0.4.0 // indirect
	golang.org/x/oauth2 v0.3.0 // indirect
	golang.org/x/sys v0.3.0 // indirect
	golang.org/x/text v0.5.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
)
