package httpauth

import (
	"net/url"
)

type SpnegoProvider interface {
	GetSPNEGOToken(url *url.URL) (string, error)
	UpdateSPNEGOToken(url *url.URL, responseToken string) (string, error)
	Close() error
}
