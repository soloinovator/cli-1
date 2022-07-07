//go:build linux || darwin
// +build linux darwin

package httpauth

import (
	"net/url"
)

type NonwindowsSpnegoProvider struct {
}

func NewNonwindowsSpnegoProvider() *NonwindowsSpnegoProvider {
	return &NonwindowsSpnegoProvider{}
}

func SpnegoProviderInstance() SpnegoProvider {
	return &NonwindowsSpnegoProvider{}
}

func (s *NonwindowsSpnegoProvider) GetToken(url *url.URL, responseToken string) (string, bool, error) {
	return "TODO", false, nil
}

func (s *NonwindowsSpnegoProvider) Close() error {
	return nil
}
