package httpauth

import (
	"net/url"
)

type SpnegoProvider interface {
	GetToken(url *url.URL, responseToken string) (string, bool, error)
	Close() error
}
