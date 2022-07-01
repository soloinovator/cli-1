package httpauth_test

import (
	"net/url"
	"testing"

	"github.com/snyk/cli/cliv2/internal/httpauth"
	"github.com/stretchr/testify/assert"
)

func Test_DisableAuthentication(t *testing.T) {

	proxyAddr, _ := url.Parse("http://127.0.0.1")
	expectedValue := ""

	authHandler := httpauth.AuthenticationHandler{
		Mechanism: httpauth.NoAuth,
	}

	actualValue, err := authHandler.GetAuthorizationValue(proxyAddr, "")
	assert.Nil(t, err)

	assert.Equal(t, expectedValue, actualValue)

}

func Test_EnabledAuthentication_Mock(t *testing.T) {

	proxyAddr, _ := url.Parse("http://127.0.0.1")
	expectedValue := "Mock"

	authHandler := httpauth.AuthenticationHandler{
		Mechanism: httpauth.Mock,
	}

	actualValue, err := authHandler.GetAuthorizationValue(proxyAddr, "")
	assert.Nil(t, err)

	assert.Contains(t, actualValue, expectedValue)

}

func Test_AuthenticationMechanismFromAndToString(t *testing.T) {

	testSet := []httpauth.AuthenticationMechanism{
		httpauth.Mock,
		httpauth.Negotiate,
		httpauth.NoAuth,
		httpauth.UnknownMechanism,
	}

	var mechanismConverted httpauth.AuthenticationMechanism
	var mechanismString string

	for _, mechanism := range testSet {
		mechanismString = httpauth.StringFromAuthenticationMechanism(mechanism)
		mechanismConverted = httpauth.AuthenticationMechanismFromString(mechanismString)
		assert.Equal(t, mechanism, mechanismConverted)
	}

}
