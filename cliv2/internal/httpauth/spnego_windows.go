package httpauth

import (
	"encoding/base64"
	"fmt"
	"github.com/alexbrainman/sspi/negotiate"
	"net/url"
)

type WindowsSpenegoProvider struct {
	clientContext *negotiate.ClientContext
}

func NewWindowsSpenegoProvider() *WindowsSpenegoProvider {
	return &WindowsSpenegoProvider{}
}

func SpenegoProviderInstance() SpnegoProvider {
	return &WindowsSpenegoProvider{}
}

func (s *WindowsSpenegoProvider) GetSPNEGOToken(url *url.URL) (string, error) {
	hostname := url.Hostname()
	// TODO: consider if we want to canonicalize the hostname

	spn := "HTTP/" + hostname

	cred, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		return "", err
	}
	defer cred.Release()

	secctx, token, err := negotiate.NewClientContext(cred, spn)
	if err != nil {
		return "", err
	}

	s.clientContext = secctx

	// defer secctx.Release()

	encodedToken := base64.StdEncoding.EncodeToString(token)
	return encodedToken, nil
}

func (s *WindowsSpenegoProvider) UpdateSPNEGOToken(url *url.URL, responseToken string) (string, error) {
	return "", fmt.Errorf("UpdateSPNEGOToken is not implemented yet (but needs to be)")
}

func (s *WindowsSpenegoProvider) Close() error {
	return s.clientContext.Release()
}
