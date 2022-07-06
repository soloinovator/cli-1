//go:build linux || darwin
// +build linux darwin

package httpauth

import (
	"fmt"
	"net/url"
)

type NonwindowsSpenegoProvider struct {
}

func NewNonwindowsSpenegoProvider() *NonwindowsSpenegoProvider {
	return &NonwindowsSpenegoProvider{}
}

func SpenegoProviderInstance() SpnegoProvider {
	return  &NonwindowsSpenegoProvider{}
}

func (s *NonwindowsSpenegoProvider) GetSPNEGOToken(url *url.URL) (string, error) {
	return "TODO", nil
}

func (s *NonwindowsSpenegoProvider) UpdateSPNEGOToken(url *url.URL, responseToken string) (string, error) {
	return "", fmt.Errorf("UpdateSPNEGOToken is not implemented for non-windows")
}

func (s *NonwindowsSpenegoProvider) Close() error {
	return nil
}
