// Package m provides gin middleware with Content Security Policy
package csphandler

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/jaynzr/cspbuilder"
)

type cspValueSetter interface {
	set(key string, value *cspbuilder.Directive)
	get(ds string) *cspbuilder.Directive
	nonce() string
}

type cspResponseWriter struct {
	http.ResponseWriter
	m map[string]*cspbuilder.Directive
	n string
}

func (w *cspResponseWriter) set(key string, d *cspbuilder.Directive) {
	if w.m == nil {
		w.m = map[string]*cspbuilder.Directive{}
	}

	w.m[key] = d
}

func (w *cspResponseWriter) get(ds string) *cspbuilder.Directive {
	var (
		d  *cspbuilder.Directive
		ok bool
	)

	if w.m == nil {
		w.m = make(map[string]*cspbuilder.Directive)
	}

	if d, ok = w.m[ds]; !ok {
		d = &cspbuilder.Directive{}
		w.m[ds] = d
	}

	return d
}

func (w *cspResponseWriter) nonce() string {
	return w.n
}

// Nonce returns the nonce value associated with the present response. If no nonce has been generated it returns an empty string.
func Nonce(w http.ResponseWriter) string {
	setter, ok := w.(cspValueSetter)
	if ok {
		return setter.nonce()
	}

	panic("wrong w type")
}

// NonceHTMLAttr returns unescaped `nonce="<nonce>"` string for use in template.
func NonceHTMLAttr(w http.ResponseWriter) template.HTMLAttr {
	return template.HTMLAttr(`nonce="` + Nonce(w) + `"`)
}

func Directive(w http.ResponseWriter, ds string) *cspbuilder.Directive {
	setter, ok := w.(cspValueSetter)
	if ok {
		return setter.get(ds)
	}
	panic("wrong w type")
}

func Hash(w http.ResponseWriter, ds string, ht cspbuilder.HashType, source string) {
	d := Directive(w, ds)
	d.Hash(ht, source)
}

// ContentSecurityPolicy implements the http.HandlerFunc for integration with the standard net/http lib.
// reportOnly sets Content-Security-Policy-Report-Only header
func ContentSecurityPolicy(pol *cspbuilder.Policy, h http.Handler, reportOnly bool) http.Handler {
	header := "Content-Security-Policy"
	if reportOnly {
		header += "-Report-Only"
	}

	pol.Build()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		cspStr := pol.Compiled
		cr := &cspResponseWriter{
			ResponseWriter: w,
		}

		if pol.RequireNonce {
			cspStr = pol.WithNonce(&cr.n)
		} else if cspStr == "" {
			cspStr = pol.Build()
		}

		cr.Header().Set(header, cspStr)
		h.ServeHTTP(cr, r)

		// TODO: csp header can't be issued after body is written.
		// Untested workaround: issue `Trailer: Content-Security-Policy` header before `h.ServeHTTP(cr, r)`
		/* if len(cr.m) > 0 {
			cspStr = pol.MergeBuild(cr.m)

			if len(cr.n) > 0 {
				cspStr = strings.ReplaceAll(cspStr, cspbuilder.Nonce, "'nonce-"+cr.n+"'")
			}
		}

		cr.Header().Set(header, cspStr) */
	})
}
