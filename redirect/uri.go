package redirect

import (
	"net/http"
	"net/url"
)

func URI(r *http.Request, callback, baseURL, schema string, disableRawQueryEmpty bool) (string, error) {
	if baseURL == "" {
		// check headers of X-Forwarded-Proto and X-Forwarded-Host
		// if they are set, use them to build the redirect uri

		proto := r.Header.Get("X-Forwarded-Proto")
		host := r.Header.Get("X-Forwarded-Host")

		if proto != "" && host != "" {
			r.URL.Scheme = proto
			r.URL.Host = host
		} else {
			// check the host header
			host := r.Host
			if host != "" {
				r.URL.Host = host
				if schema != "" {
					r.URL.Scheme = schema
				} else {
					r.URL.Scheme = "https"
				}
			}
		}
	} else {
		urlParsed, err := url.Parse(baseURL)
		if err != nil {
			return "", err
		}

		r.URL.Scheme = urlParsed.Scheme
		r.URL.Host = urlParsed.Host
	}

	if callback != "" {
		r.URL.Path = callback
	}

	if !disableRawQueryEmpty {
		r.URL.RawQuery = ""
	}

	return r.URL.String(), nil
}
