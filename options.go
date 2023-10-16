package auth

type optionsActiveProvider struct {
	noop   bool
	active string
}

type OptionActiveProvider func(options *optionsActiveProvider)

// WithNoop sets the active provider to noop.
func WithNoop(v bool) OptionActiveProvider {
	return func(options *optionsActiveProvider) {
		options.noop = v
	}
}

func WithActive(provider string) OptionActiveProvider {
	return func(options *optionsActiveProvider) {
		options.active = provider
	}
}
