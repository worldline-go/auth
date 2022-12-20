package auth

type optionsParser struct {
	jwt bool
}

type OptionParser func(options *optionsParser)

func WithJwt() OptionParser {
	return func(options *optionsParser) {
		options.jwt = true
	}
}

type optionsJWK struct {
	refreshErrorHandler func(err error)
}

type OptionJWK func(options *optionsJWK)

func WithRefreshErrorHandler(fn func(err error)) OptionJWK {
	return func(options *optionsJWK) {
		options.refreshErrorHandler = fn
	}
}
