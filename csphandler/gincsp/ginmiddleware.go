// Package gincsp is a gin middleware that supports Content Security Policy
package gincsp

import (
	"html/template"

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

// NonceHTMLAttr returns unescaped `nonce="<nonce>"` string for use in template.
func NonceHTMLAttr(c *gin.Context) template.HTMLAttr {
	return template.HTMLAttr(`nonce="` + Nonce(c) + `"`)
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

// ContentSecurityPolicy implements the gin.HandlerFunc. Does not support dynamically calculated hashes
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
			cspStr = pol.Compiled
		)

		if pol.RequireNonce {
			cspStr = pol.WithNonce(&nonce)
			c.Set(cspNonceKey, nonce)
		} else if cspStr == "" {
			cspStr = pol.Build()
		}

		c.Header(header, cspStr)
		c.Next()
	}
}
