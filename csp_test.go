package cspbuilder_test

import (
	"strings"
	"testing"

	"github.com/jaynzr/cspbuilder"
)

var tests = [][]string{
	{cspbuilder.Img, "img-src 'self' www.google.com/recaptcha/", cspbuilder.Self, "www.google.com/recaptcha/"},
	{cspbuilder.Script, "script-src cdnjs.cloudflare.com cdn.jsdelivr.net www.google-analytics.com 'unsafe-inline' data: $NONCE 'strict-dynamic'", "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "www.google-analytics.com", cspbuilder.UnsafeInline, cspbuilder.Data, cspbuilder.Nonce, cspbuilder.StrictDynamic},
	{cspbuilder.RequireTrustedTypesFor, "require-trusted-types-for 'script'", cspbuilder.TrustedScript},
}

func setup(i int) *cspbuilder.Policy {
	pol := cspbuilder.New()
	pol.UpgradeInsecureRequests = true

	s := tests[i]

	d := pol.New(s[0])

	if len(s) > 2 {
		d.Add(s[2:]...)
	}

	pol.ReportURI = "/_csp-report"

	return pol
}

func TestCspBuilder(t *testing.T) {
	var (
		nonce string
		pol   *cspbuilder.Policy
	)

	for i, test := range tests {
		nonce = ""

		pol = setup(i)
		t.Log(pol.Build())

		if !strings.Contains(pol.Compiled, test[1]) {
			t.Fatal("want", test[1], "got", pol.Compiled)
		}

		if pol.RequireNonce {
			cspnonce := pol.WithNonce(&nonce)
			t.Log(nonce, cspnonce)
			if len(cspnonce) == len(pol.Compiled) || !strings.Contains(cspnonce, "'nonce-" + nonce + "'") {
				t.Fatal("nonce required", nonce, "got", cspnonce)
			}
		}
	}

}

func TestR1(t *testing.T) {
	pol := cspbuilder.Starter()
	pol.UpgradeInsecureRequests = true

    // add script-src
	var d *cspbuilder.Directive = pol.New(cspbuilder.Script, "cdnjs.cloudflare.com", "cdn.jsdelivr.net")
	d.Hash(cspbuilder.SHA512, `doSomething()`)
	d.Add("www.google-analytics.com", cspbuilder.UnsafeInline, cspbuilder.Data)

    // add style-src
	d = pol.New(cspbuilder.Style)
	d.Add(cspbuilder.Self, cspbuilder.UnsafeInline, "cdnjs.cloudflare.com", "fonts.googleapis.com")

    // add img-src
	pol.New(cspbuilder.Img, cspbuilder.All)

    // add font-src
	pol.New(cspbuilder.Font, "fonts.googleapis.com", "fonts.gstatic.com")

    // add frame-ancestors
	pol.New(cspbuilder.FrameAncestors)

    // experimental csp v3 require-trusted-types-for
    pol.New(cspbuilder.RequireTrustedTypesFor, cspbuilder.TrustedScript)

	pol.ReportURI = "/_csp-report"

    pol.Build()

	t.Log(pol.Compiled)
}

func TestMerge(t *testing.T) {
	want := "script-src 'self' 'sha512-NrS2FABurNzIW2yTKRxF8X+HMhJh29vd9syOLut1MW4Cd1JeGzZqughLzC+LQr0O8XFhCuR4zyjLgrTQct7jAA=='"
	pol := cspbuilder.Starter()
	pol.UpgradeInsecureRequests = true

    // add script-src
	pol.New(cspbuilder.Script, cspbuilder.Self)

	d := &cspbuilder.Directive{}
	d.Hash(cspbuilder.SHA512, `doSomething()`)

	s := pol.MergeBuild(map[string]*cspbuilder.Directive{cspbuilder.Script: d})

	t.Log(s)

	if !strings.Contains(pol.Compiled, want) {
		t.Fatal("want", want, "got", pol.Compiled)
	}
}

func TestNonce(t *testing.T) {
	var (
		nonce string
		pol   = cspbuilder.Starter()
	)

	d := pol.New(cspbuilder.Script, cspbuilder.Nonce)

	cspnonce := pol.WithNonce(&nonce)
	t.Log(nonce, cspnonce)

	if !pol.RequireNonce {
		t.Fatal("RequireNonce = false")
	}

	if len(cspnonce) == len(pol.Compiled) || !strings.Contains(cspnonce, "'nonce-" + nonce + "'") {
		t.Fatal("nonce required", nonce, "got", cspnonce)
	}

	d.Hash(cspbuilder.SHA512, `doSomething()`)
	pol.Build()

	if !strings.Contains(pol.Compiled, "'sha512-NrS2FABurNzIW2yTKRxF8X+HMhJh29vd9syOLut1MW4Cd1JeGzZqughLzC+LQr0O8XFhCuR4zyjLgrTQct7jAA==") {
		t.Fatal("want", "", "got", pol.Compiled)
	}
}

func BenchmarkCsp(b *testing.B) {
	for i := 0; i < b.N; i++ {
		pol := setup(1)
		pol.Build()
	}
}

func BenchmarkNonceCsp(b *testing.B) {
	pol := setup(1)
	pol.Build()

	for i := 0; i < b.N; i++ {
		var nonce string
		pol.WithNonce(&nonce)
	}
}
