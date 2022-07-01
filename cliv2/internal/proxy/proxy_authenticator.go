package proxy

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/snyk/cli/cliv2/internal/httpauth"
	"golang.org/x/net/idna"
)

type ProxyAuthenticator struct {
	acceptedProxyAuthMechanism httpauth.AuthenticationMechanism
	debugLogger                *log.Logger
	upstreamProxy              func(*http.Request) (*url.URL, error)
}

func (p *ProxyAuthenticator) ConnectToProxy(ctx context.Context, proxyURL *url.URL, target string, connection net.Conn) error {

	var err error
	var token string
	var responseToken string

	if connection == nil {
		return fmt.Errorf("No connection available!")
	}

	if p.acceptedProxyAuthMechanism != httpauth.NoAuth {
		if proxyURL != nil {
			authHandler := &httpauth.AuthenticationHandler{
				Mechanism: p.acceptedProxyAuthMechanism,
				State:     httpauth.Initial,
			}

			p.debugLogger.Println("Proxy Address:", proxyURL)
			p.debugLogger.Printf("Connection to %s from %s via %s\n", target, connection.LocalAddr(), connection.RemoteAddr())

			for !authHandler.IsStopped() {

				proxyConnectHeader := make(http.Header)
				var response *http.Response
				var responseError error

				if token, err = authHandler.GetAuthorizationValue(proxyURL, responseToken); err == nil {

					if len(token) > 0 {
						proxyConnectHeader.Add(httpauth.ProxyAuthorizationKey, token)
						p.debugLogger.Printf("CONNECT Header added %s: %s\n", httpauth.ProxyAuthorizationKey, token)
					} else {
						p.debugLogger.Printf("CONNECT Header NOT added \"%s\" (empty)\n", httpauth.ProxyAuthorizationKey)
					}

					//
					if !authHandler.IsStopped() {
						// send connect
						response, responseError = p.Send(ctx, connection, &http.Request{
							Method: "CONNECT",
							URL:    &url.URL{Opaque: target},
							Host:   target,
							Header: proxyConnectHeader,
						})

						if response != nil && response.StatusCode == 407 {
							detectedMechanism := httpauth.NoAuth

							result := response.Header.Values(httpauth.ProxyAuthenticateKey)
							if len(result) == 1 {
								authenticateValue := strings.Split(result[0], " ")
								p.debugLogger.Printf("Proxy-Authenticate: %s\n", authenticateValue)

								if len(authenticateValue) >= 1 {
									detectedMechanism = httpauth.AuthenticationMechanismFromString(authenticateValue[0])
									p.debugLogger.Printf("Detected Mechanism: %d (%s)\n", detectedMechanism, authenticateValue[0])
								}

								if len(authenticateValue) == 2 {
									responseToken = authenticateValue[1]
								} else {
									responseToken = ""
								}

								p.debugLogger.Printf("Response Token: %s\n", responseToken)
							}

							if detectedMechanism != p.acceptedProxyAuthMechanism {
								authHandler.Cancel()
								err = fmt.Errorf("Incorrect Mechanism detected! %s", result)
							}
						} else if response != nil && response.StatusCode == 200 {
							authHandler.Succesful()
						}
					} else if responseError != nil {
						authHandler.Cancel()
						err = fmt.Errorf("Failed to CONNECT to proxy! %v", responseError)
					}
				} else {
					authHandler.Cancel()
					err = fmt.Errorf("Failed to retreive Proxy Authorization! %v", err)
				}
			}
		} else {
			err = fmt.Errorf("Given proxyUrl must not be nil!")
		}
	}

	return err
}

func (p *ProxyAuthenticator) GetDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var connection net.Conn
	var err error
	var proxyUrl *url.URL

	fakeRequest := &http.Request{URL: &url.URL{}}
	fakeRequest.URL.Scheme = LookupSchemeFromCannonicalAddress(addr, "https")
	proxyUrl, err = p.upstreamProxy(fakeRequest)

	if err != nil {
		return nil, err
	}

	proxyAddr := canonicalAddr(proxyUrl)

	p.debugLogger.Printf("Dial context: CONNECT %s via %s\n", addr, proxyAddr)

	connection, err = net.Dial(network, proxyAddr)
	if err == nil {
		err = p.ConnectToProxy(ctx, proxyUrl, addr, connection)
	}

	return connection, err
}

func LookupSchemeFromCannonicalAddress(addr string, defaultScheme string) string {
	result := defaultScheme
	port := ""
	tempAddr := strings.Split(addr, ":")
	tempAddrLen := len(tempAddr)
	if tempAddrLen >= 2 {
		port = tempAddr[tempAddrLen-1]
	}

	for k, v := range portMap {
		if v == port {
			result = k
		}
	}
	return result
}

// the following code is partially taken from net/http/transport.go ----

// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// HTTP client implementation. See RFC 7230 through 7235.
//
// This is the low-level Transport implementation of RoundTripper.
// The high-level interface is in client.go.

func (p *ProxyAuthenticator) Send(ctx context.Context, connection net.Conn, request *http.Request) (*http.Response, error) {

	// If there's no done channel (no deadline or cancellation
	// from the caller possible), at least set some (long)
	// timeout here. This will make sure we don't block forever
	// and leak a goroutine if the connection stops replying
	// after the TCP connect.
	connectCtx := ctx
	if ctx.Done() == nil {
		newCtx, cancel := context.WithTimeout(ctx, 1*time.Minute)
		defer cancel()
		connectCtx = newCtx
	}

	didReadResponse := make(chan struct{}) // closed after CONNECT write+read is done or fails
	var (
		resp *http.Response
		err  error // write or read error
	)
	// Write the CONNECT request & read the response.
	go func() {
		defer close(didReadResponse)
		err = request.Write(connection)
		if err != nil {
			return
		}
		// Okay to use and discard buffered reader here, because
		// TLS server will not speak until spoken to.
		br := bufio.NewReader(connection)
		resp, err = http.ReadResponse(br, request)
		if err != nil {
			return
		}
	}()
	select {
	case <-connectCtx.Done():
		connection.Close()
		<-didReadResponse
		return nil, connectCtx.Err()
	case <-didReadResponse:
		// resp or err now set
	}

	//fmt.Println("Send() ------------------------------------------------------------------------------------------------------------------------")
	//fmt.Println("Send() - Request: ", request)
	//fmt.Println("Send() - Response: ", resp)
	//fmt.Println("Send() ------------------------------------------------------------------------------------------------------------------------")

	return resp, nil
}

var portMap = map[string]string{
	"http":   "80",
	"https":  "443",
	"socks5": "1080",
}

// canonicalAddr returns url.Host but always with a ":port" suffix
func canonicalAddr(url *url.URL) string {
	addr := url.Hostname()
	if v, err := idna.Lookup.ToASCII(addr); err == nil {
		addr = v
	}
	port := url.Port()
	if port == "" {
		port = portMap[url.Scheme]
	}
	return net.JoinHostPort(addr, port)
}
