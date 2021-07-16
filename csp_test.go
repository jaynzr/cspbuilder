package cspbuilder_test

import (
	"testing"

	"github.com/jaynzr/cspbuilder"
)

func setup() *cspbuilder.Policy {
	pol := cspbuilder.New()
	pol.UpgradeInsecureRequests = true

	pol.With(cspbuilder.Img, &cspbuilder.Directive{SourceFlag: cspbuilder.Self, Sources: []string{"www.google.com/recaptcha/"}})

	d := pol.New(cspbuilder.Script, "cdnjs.cloudflare.com", "cdn.jsdelivr.net")
	d.Hash(cspbuilder.SHA512, `doSomething()`)
	d.Fetch("www.google-analytics.com")
	d.SourceFlag = cspbuilder.UnsafeInline | cspbuilder.Data | cspbuilder.RequireNonce | cspbuilder.StrictDynamic

	d = pol.New(cspbuilder.Style)
	d.SourceFlag = cspbuilder.Self | cspbuilder.UnsafeInline
	d.Fetch("cdnjs.cloudflare.com", "fonts.googleapis.com")

	d = pol.New(cspbuilder.Connect)
	d.SourceFlag = cspbuilder.All

	d = pol.New(cspbuilder.RequireTrustedTypesFor)
	d.Fetch("'script'")

	pol.New(cspbuilder.Font, "fonts.googleapis.com", "fonts.gstatic.com")

	pol.New(cspbuilder.FrameAncestors)

	pol.ReportURI = "/_csp-report"

	return pol
}

func TestCspBuilder(t *testing.T) {
	var (
		nonce string
		pol   = setup()
	)

	t.Log(pol.Build())
	t.Log(pol.WithNonce(&nonce))
	t.Log(nonce)
}

func BenchmarkCsp(b *testing.B) {
	for i := 0; i < b.N; i++ {
		pol := setup()
		pol.Build()
	}
}

func BenchmarkNonceCsp(b *testing.B) {
	pol := setup()
	pol.Build()

	for i := 0; i < b.N; i++ {
		var nonce string
		pol.WithNonce(&nonce)
	}
}
