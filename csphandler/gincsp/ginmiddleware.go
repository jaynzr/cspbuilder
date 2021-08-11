// Package gincsp is a gin middleware that supports Content Security Policy
package gincsp

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jaynzr/cspbuilder"
)

const (
	cspNonceKey   = "cspNonce"
	cspDirsMapKey = "cspDirsMap"
)

func Nonce(c *gin.Context) string {
	return c.GetString(cspNonceKey)
}

func Directive(c *gin.Context, ds string) *cspbuilder.Directive {
	var (
		m  = getMap(c)
		d  *cspbuilder.Directive
		ok bool
	)

	if d, ok = m[ds]; !ok {
		d = &cspbuilder.Directive{}
		m[ds] = d
	}

	return d
}

func Hash(c *gin.Context, ds string, ht cspbuilder.HashType, source string) {
	var (
		m  = getMap(c)
		d  *cspbuilder.Directive
		ok bool
	)

	if d, ok = m[ds]; !ok {
		d = &cspbuilder.Directive{}
		m[ds] = d
	}

	d.Hash(ht, source)
	c.Set(cspDirsMapKey, m)
}

func getMap(c *gin.Context) map[string]*cspbuilder.Directive {
	var (
		m map[string]*cspbuilder.Directive
	)

	if _m, ok := c.Get(cspDirsMapKey); ok {
		m = _m.(map[string]*cspbuilder.Directive)
	} else {
		m = make(map[string]*cspbuilder.Directive)
	}

	return m
}

// ContentSecurityPolicy implements the gin.HandlerFunc.
// reportOnly sets Content-Security-Policy-Report-Only header
func ContentSecurityPolicy(pol *cspbuilder.Policy, reportOnly bool) gin.HandlerFunc {
	header := "Content-Security-Policy"
	if reportOnly {
		header += "-Report-Only"
	}

	pol.Build()

	return func(c *gin.Context) {
		var (
			nonce  string
			m      map[string]*cspbuilder.Directive
			cspStr = pol.Compiled
		)

		if pol.RequireNonce {
			cspStr = pol.WithNonce(&nonce)
			c.Set(cspNonceKey, nonce)
		} else if cspStr == "" {
			cspStr = pol.Build()
		}

		c.Next()

		m = getMap(c)
		if len(m) > 0 {
			cspStr = pol.MergeBuild(m)

			if len(nonce) > 0 {
				cspStr = strings.ReplaceAll(cspStr, cspbuilder.Nonce, "'nonce-"+nonce+"'")
			}
		}

		c.Header(header, cspStr)
	}
}
