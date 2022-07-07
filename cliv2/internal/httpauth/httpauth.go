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
	Close       AuthenticationState = iota
)

const (
	AuthorizationKey      string = "Authorization"
	ProxyAuthorizationKey string = "Proxy-Authorization"
	ProxyAuthenticateKey  string = "Proxy-Authenticate"
)

type AuthenticationHandler struct {
	spnegoProvider SpnegoProvider
	Mechanism      AuthenticationMechanism
	state          AuthenticationState
	cycleCount     int
}

func NewHandler(mechanism AuthenticationMechanism) *AuthenticationHandler {
	a := &AuthenticationHandler{
		spnegoProvider: SpnegoProviderInstance(), // TODO: don't for get to call .Close() on this
		Mechanism:      mechanism,
		state:          Initial,
	}
	return a
}

func (a *AuthenticationHandler) Close() {
	a.spnegoProvider.Close()
	a.state = Close
}

func (a *AuthenticationHandler) GetAuthorizationValue(url *url.URL, responseToken string) (string, error) {
	authorizeValue := ""
	mechanism := string(a.Mechanism)

	if a.Mechanism == Negotiate { // supporting mechanism: Negotiate (SPNEGO)
		var err error
		var token string
		var done bool

		a.state = Negotiating

		token, done, err = a.spnegoProvider.GetToken(url, responseToken)
		if err != nil {
			a.state = Error
			return "", err
		}

		if done {
			a.state = Done
		}

		authorizeValue = mechanism + " " + token
	} else if a.Mechanism == Mock { // supporting mechanism: Mock for testing
		authorizeValue = mechanism + " " + responseToken
		a.state = Done
	}

	a.cycleCount++

	return authorizeValue, nil
}

func (a *AuthenticationHandler) IsStopped() bool {
	return (a.state == Done || a.state == Error || a.state == Cancel || a.state == Close || a.cycleCount >= maxCycleCount)
}

func (a *AuthenticationHandler) Reset() {
	a.state = Initial
	a.cycleCount = 0
}

func (a *AuthenticationHandler) Cancel() {
	a.state = Cancel
}

func (a *AuthenticationHandler) Succesful() {
	a.state = Done
}

func StringFromAuthenticationMechanism(mechanism AuthenticationMechanism) string {
	return string(mechanism)
}

func AuthenticationMechanismFromString(mechanism string) AuthenticationMechanism {
	return AuthenticationMechanism(mechanism)
}
