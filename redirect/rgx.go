package redirect

import (
	"net/http"
	"regexp"
)

var regexRedirection = regexp.MustCompile(`^(/[^.]*(\.html)?|/?)$`)

func RegexCheck(r *http.Request, information *RedirectMatch) (bool, error) {
	if information.rgx == nil {
		if information.Regex == "" {
			information.rgx = regexRedirection
		} else {
			var err error
			information.rgx, err = regexp.Compile(information.Regex)
			if err != nil {
				return false, err
			}
		}
	}

	if information.NoHeaderKeyValues == nil {
		information.NoHeaderKeyValues = map[string]string{
			"X-Requested-With": "XMLHttpRequest",
		}
	}

	for key, value := range information.NoHeaderKeyValues {
		if r.Header.Get(key) == value {
			return false, nil
		}
	}

	if information.NoHeaderKeys == nil {
		information.NoHeaderKeys = []string{
			"Content-Type",
		}
	}

	for _, key := range information.NoHeaderKeys {
		if r.Header.Get(key) != "" {
			return false, nil
		}
	}

	ok := information.rgx.MatchString(r.URL.Path)

	return ok, nil
}
