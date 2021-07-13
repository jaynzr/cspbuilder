package cspbuilder_test

import (
	"testing"

	"github.com/jaynzr/cspbuilder"
)

func TestCspBuilder(t *testing.T) {
	var nonce string
	pol := cspbuilder.New()
	pol.UpgradeInsecureRequests = true

	pol.With(cspbuilder.Img, &cspbuilder.Directive{Self: true, Sources: []string{"www.google.com/recaptcha/"}})

	d := pol.New(cspbuilder.Script, "cdnjs.cloudflare.com", "cdn.jsdelivr.net")
	d.Hash(cspbuilder.SHA512, `doSomething()`)
	d.Fetch("www.google-analytics.com")
	d.Nonce(true, true)
	d.UnsafeInline = true

	d = pol.New(cspbuilder.Style)
	d.Self = true
	d.UnsafeInline = true
	d.Fetch("cdnjs.cloudflare.com", "fonts.googleapis.com")

	d = pol.New(cspbuilder.RequireTrustedTypesFor)
	d.Fetch("'script'")

	pol.New(cspbuilder.Font, "fonts.googleapis.com", "fonts.gstatic.com")

	pol.New(cspbuilder.FrameAncestors)

	pol.ReportURI = "/_csp-report"

	t.Log(pol.Build())

	t.Log(pol.WithNonce(&nonce))
	t.Log(nonce)
}
