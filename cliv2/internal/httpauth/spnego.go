package httpauth

import (
	"log"
	"net/url"
)

type SpnegoProvider interface {
	GetToken(url *url.URL, responseToken string) (string, bool, error)
	Close() error
	SetLogger(logger *log.Logger)
}
