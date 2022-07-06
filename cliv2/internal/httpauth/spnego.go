package httpauth

import (
	"net/url"
)

type SpnegoProvider interface {
	GetSPNEGOToken(url *url.URL, responseToken string) (string, bool, error)
	Close() error
}
