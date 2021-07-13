package gincsp

import (
	"github.com/gin-gonic/gin"
	"github.com/jaynzr/cspbuilder"
)

func CSP(pol *cspbuilder.Policy, reportOnly bool) gin.HandlerFunc {
	header := "Content-Security-Policy"
	if reportOnly {
		header += "-Report-Only"
	}

	pol.Build()

	return func(c *gin.Context) {
		var (
			nonce     string
			cspString = pol.Built
		)

		if pol.HasNonce {
			cspString = pol.WithNonce(&nonce)
			c.Set("cspNonce", nonce)
		}

		c.Header(header, cspString)
	}
}
