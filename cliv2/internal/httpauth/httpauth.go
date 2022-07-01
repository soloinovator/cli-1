package httpauth

import (
	"net/http"
	"net/url"

	"github.com/dpotapov/go-spnego"
)

type AuthenticationMechanism int
type AuthenticationState int

const maxCycleCount int = 10

const (
	NoAuth           AuthenticationMechanism = iota
	Mock             AuthenticationMechanism = iota
	Negotiate        AuthenticationMechanism = iota
	UnknownMechanism AuthenticationMechanism = iota
)

const (
	Initial     AuthenticationState = iota
	Negotiating AuthenticationState = iota
	Done        AuthenticationState = iota
	Error       AuthenticationState = iota
	Cancel      AuthenticationState = iota
)

const (
	AuthorizationKey      string = "Authorization"
	ProxyAuthorizationKey string = "Proxy-Authorization"
	ProxyAuthenticateKey  string = "Proxy-Authenticate"
)

type AuthenticationHandler struct {
	Mechanism  AuthenticationMechanism
	State      AuthenticationState
	cycleCount int
}

func (a *AuthenticationHandler) GetAuthorizationValue(url *url.URL, responseToken string) (string, error) {

	var authorizeValue string

	tmpRequest := http.Request{
		URL:    url,
		Header: map[string][]string{},
	}

	if a.Mechanism == Negotiate { // supporting mechanism: Negotiate (SPNEGO)

		if Negotiating == a.State {
			var provider spnego.Provider = spnego.New()
			cannonicalize := false

			// todo: forward response token to provider
			if err := provider.SetSPNEGOHeader(&tmpRequest, cannonicalize); err != nil {
				a.State = Error
				return "", err
			}

			// todo: check if the security context is done!
		} else if Initial == a.State {
			a.State = Negotiating
		}

	} else if a.Mechanism == Mock { // supporting mechanism: Mock for testing
		tmpRequest.Header.Set(AuthorizationKey, "Mock "+responseToken)
		a.State = Done
	}

	// ugly work around the fact that go-spnego only adds an "Authorize" Header and not "Proxy-Authorize"
	if a.Mechanism != NoAuth {
		authorizeValue = tmpRequest.Header.Get(AuthorizationKey)
	}

	a.cycleCount++

	return authorizeValue, nil
}

func (a *AuthenticationHandler) IsStopped() bool {
	return (a.State == Done || a.State == Error || a.State == Cancel || a.cycleCount >= maxCycleCount)
}

func (a *AuthenticationHandler) Reset() {
	a.State = Initial
	a.cycleCount = 0
}

func (a *AuthenticationHandler) Cancel() {
	a.State = Cancel
}

func (a *AuthenticationHandler) Succesful() {
	a.State = Done
}

func StringFromAuthenticationMechanism(mechanism AuthenticationMechanism) string {
	var result string
	switch mechanism {
	case NoAuth:
		result = "NoAuth"
	case Negotiate:
		result = "Negotiate"
	case Mock:
		result = "Mock"
	default:
		result = "Unknonwn AuthenticationMechanism"
	}
	return result
}

func AuthenticationMechanismFromString(mechanism string) AuthenticationMechanism {
	var result AuthenticationMechanism
	switch mechanism {
	case "NoAuth":
		result = NoAuth
	case "Negotiate":
		result = Negotiate
	case "Mock":
		result = Mock
	default:
		result = UnknownMechanism
	}
	return result
}
