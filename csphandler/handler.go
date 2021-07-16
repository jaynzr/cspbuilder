// Package m provides gin middleware with Content Security Policy
package csphandler

import (
	"context"
	"net/http"

	"github.com/jaynzr/cspbuilder"
)

type key int
const cspNonceKey key = iota

type ContentSecurityPolicy struct {
	cspbuilder.Policy

	// ReportOnly sets Content-Security-Policy-Report-Only header
	ReportOnly bool
}

// Nonce returns the nonce value associated with the present request. If no nonce has been generated it returns an empty string.
func Nonce(c context.Context) string {
	if val, ok := c.Value(cspNonceKey).(string); ok {
		return val
	}

	return ""
}

func withCSPNonce(r *http.Request, nonce string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), cspNonceKey, nonce))
}

// Handler implements the http.HandlerFunc for integration with the standard net/http lib.
func (csp ContentSecurityPolicy) Handler(h http.Handler) http.Handler {
	header := "Content-Security-Policy"
	if csp.ReportOnly {
		header += "-Report-Only"
	}

	csp.Policy.Build()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var (
			nonce     string
			cspString = csp.Policy.Compiled
		)

		if csp.Policy.RequireNonce {
			cspString = csp.Policy.WithNonce(&nonce)
			r = withCSPNonce(r, nonce)
		} else if cspString == "" {
			cspString = csp.Policy.Build()
		}

		w.Header().Set(header, cspString)

		h.ServeHTTP(w, r)
	})
}
