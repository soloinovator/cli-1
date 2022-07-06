//go:build linux || darwin
// +build linux darwin

package httpauth

import (
	"net/url"
)

type NonwindowsSpenegoProvider struct {
}

func NewNonwindowsSpenegoProvider() *NonwindowsSpenegoProvider {
	return &NonwindowsSpenegoProvider{}
}

func SpenegoProviderInstance() SpnegoProvider {
	return &NonwindowsSpenegoProvider{}
}

func (s *NonwindowsSpenegoProvider) GetSPNEGOToken(url *url.URL, responseToken string) (string, bool, error) {
	return "TODO", false, nil
}

func (s *NonwindowsSpenegoProvider) Close() error {
	return nil
}
