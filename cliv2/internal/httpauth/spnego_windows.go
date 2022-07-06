package httpauth

import (
	"encoding/base64"
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

func (s *WindowsSpenegoProvider) init(url *url.URL) ([]byte, error) {
	hostname := url.Hostname()
	token := []byte{}

	spn := "HTTP/" + hostname

	cred, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		return token, err
	}
	defer cred.Release()

	secctx, token, err := negotiate.NewClientContext(cred, spn)
	if err != nil {
		return token, err
	}

	s.clientContext = secctx
	return token, nil
}

func (s *WindowsSpenegoProvider) update(responseToken string) ([]byte, bool, error) {
	var decodedToken []byte
	var newRequesToken []byte
	var err error
	done := false

	decodedToken, err = base64.StdEncoding.DecodeString(responseToken)
	if err != nil {
		return newRequesToken, done, err
	}

	done, newRequesToken, err = s.clientContext.Update(decodedToken)

	return newRequesToken, done, err
}

func (s *WindowsSpenegoProvider) GetSPNEGOToken(url *url.URL, responseToken string) (string, bool, error) {
	var err error
	var token []byte
	done := false

	if s.clientContext == nil {
		token, err = s.init(url)
	} else {
		token, done, err = s.update(responseToken)
	}

	encodedToken := base64.StdEncoding.EncodeToString(token)
	return encodedToken, done, err
}

func (s *WindowsSpenegoProvider) Close() error {
	return s.clientContext.Release()
}
