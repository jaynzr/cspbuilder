// Package gincsp is a gin middleware that supports Content Security Policy
package gincsp

import (
	"github.com/gin-gonic/gin"
	"github.com/jaynzr/cspbuilder"
)

const CSPNONCE = "cspNonce"

func Nonce(c *gin.Context) string {
	return	c.GetString(CSPNONCE)
}

func ContentSecurityPolicy(pol *cspbuilder.Policy, reportOnly bool) gin.HandlerFunc {
	header := "Content-Security-Policy"
	if reportOnly {
		header += "-Report-Only"
	}

	pol.Build()

	return func(c *gin.Context) {
		var (
			nonce     string
			cspString = pol.Compiled
		)

		if pol.RequireNonce {
			cspString = pol.WithNonce(&nonce)
			c.Set(CSPNONCE, nonce)
		} else if cspString == "" {
			cspString = pol.Build()
		}

		c.Header(header, cspString)
	}
}
