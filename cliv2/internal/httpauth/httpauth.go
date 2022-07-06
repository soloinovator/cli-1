package httpauth

import (
	"net/url"
)

type AuthenticationMechanism string
type AuthenticationState int

const maxCycleCount int = 10

const (
	NoAuth           AuthenticationMechanism = "NoAuth"
	Mock             AuthenticationMechanism = "Mock"
	Negotiate        AuthenticationMechanism = "Negotiate"
	UnknownMechanism AuthenticationMechanism = "UnknownMechanism"
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
	SpnegoProvider SpnegoProvider
	Mechanism      AuthenticationMechanism
	State          AuthenticationState
	cycleCount     int
}

func (a *AuthenticationHandler) GetAuthorizationValue(url *url.URL, responseToken string) (string, error) {
	authorizeValue := ""
	mechanism := string(a.Mechanism)

	if a.Mechanism == Negotiate { // supporting mechanism: Negotiate (SPNEGO)
		// todo: check if the security context is done!

		if a.State == Initial {
			// initial => no authorization is done
			a.State = Negotiating
		} else if a.State == Negotiating {
			var err error
			var token string
			var done bool

			token, done, err = a.SpnegoProvider.GetSPNEGOToken(url, responseToken)
			if err != nil {
				a.State = Error
				return "", err
			}

			if done {
				a.State = Done
			}

			authorizeValue = mechanism + " " + token
		}
	} else if a.Mechanism == Mock { // supporting mechanism: Mock for testing
		// tmpRequest.Header.Set(AuthorizationKey, "Mock "+responseToken)
		authorizeValue = mechanism + " " + responseToken
		a.State = Done
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
	return string(mechanism)
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
