package httpauth

import (
	"fmt"
	"net/url"
)

type AuthenticationMechanism int
type AuthenticationState int

const maxCycleCount int = 3

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
	SpnegoProvider SpnegoProvider
	Mechanism      AuthenticationMechanism
	State          AuthenticationState
	cycleCount     int
}

func (a *AuthenticationHandler) GetAuthorizationValue(url *url.URL, responseToken string) (string, error) {
	authorizeValue := ""

	if a.Mechanism == Negotiate { // supporting mechanism: Negotiate (SPNEGO)
		// todo: check if the security context is done!

		if a.State == Initial {
			fmt.Println("a.State: Initial")
			a.State = Negotiating

		} else if a.State == Negotiating {
			fmt.Println("a.State: Negotiating")
			t, err := a.SpnegoProvider.GetSPNEGOToken(url)
			if err != nil {
				a.State = Error
				return "", err
			}
			authorizeValue = t
		}
	} else if a.Mechanism == Mock { // supporting mechanism: Mock for testing
		// tmpRequest.Header.Set(AuthorizationKey, "Mock "+responseToken)
		authorizeValue = "Mock " + responseToken
		a.State = Done
	}

	a.cycleCount++
	fmt.Println("a.cycleCount:", a.cycleCount)

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
