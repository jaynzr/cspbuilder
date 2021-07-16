# CSP Builder
Content Security Policy (CSP) builder and middleware for Go.

This allows you to create CSP with Go and integrate with a web framework or http/net.

Supports CSP v3

# Installation
```golang
$ go get -u github.com/jaynzr/csphandler
```

# Simple Usage: Creating Static CSP String
```golang

import "github.com/jaynzr/cspbuilder"
import "fmt"

func main() {
    // Starter() creates policy with sensible defaults.
    // default-src 'none';base-uri 'self';script-src 'self';connect-src 'self';img-src 'self';style-src 'self';form-action 'self'
    // use cspbuilder.Policy{} or cspbuilder.New() to start with empty policy
    pol := cspbuilder.Starter()
	pol.UpgradeInsecureRequests = true

    // add script-src
	d := pol.New(cspbuilder.Script, "cdnjs.cloudflare.com", "cdn.jsdelivr.net")
	d.Hash(cspbuilder.SHA512, `doSomething()`)
	d.Fetch("www.google-analytics.com")
	d.SourceFlag = cspbuilder.UnsafeInline | cspbuilder.Data

    // add style-src
	d = pol.New(cspbuilder.Style)
	d.SourceFlag = cspbuilder.Self | cspbuilder.UnsafeInline
	d.Fetch("cdnjs.cloudflare.com", "fonts.googleapis.com")

    // add connect-src
	d = pol.New(cspbuilder.Connect)
	d.SourceFlag = cspbuilder.All

    // add font-src
	pol.New(cspbuilder.Font, "fonts.googleapis.com", "fonts.gstatic.com")

    // add frame-ancestors
	pol.New(cspbuilder.FrameAncestors)

    // experimental csp v3 require-trusted-types-for
    d = pol.New(cspbuilder.RequireTrustedTypesFor)
	d.Fetch("'script'")

	pol.ReportURI = "/_csp-report"

    pol.Build()

    fmt.Println(pol.Compiled)
    // default-src 'none';base-uri 'self';img-src 'self' www.google.com/recaptcha/;style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com fonts.googleapis.com;form-action 'self';font-src fonts.googleapis.com fonts.gstatic.com;frame-ancestors 'none';script-src 'unsafe-inline' data: cdnjs.cloudflare.com cdn.jsdelivr.net 'sha512-NrS2FABurNzIW2yTKRxF8X+HMhJh29vd9syOLut1MW4Cd1JeGzZqughLzC+LQr0O8XFhCuR4zyjLgrTQct7jAA==' www.google-analytics.com;connect-src *;require-trusted-types-for 'script';upgrade-insecure-requests;report-uri /_csp-report
}

```

# Usage with Nonce
```golang
import "github.com/jaynzr/cspbuilder"
import "fmt"

func main() {
    var nonce string
    // start with blank policy
    pol := cspbuilder.New()

	d := pol.New(cspbuilder.Script)

    // add unsafe-line, data:, strict-dynamic, nonce sources to script-src
	d.SourceFlag = cspbuilder.UnsafeInline | cspbuilder.Data | cspbuilder.RequireNonce | cspbuilder.StrictDynamic

    pol.Build()

    fmt.Println(pol.Compiled)
    // Placeholder value $NONCE is added to the policy.
    // script-src $NONCE 'strict-dynamic' 'unsafe-inline' data:

    // WithNonce() to generate random base64 encoded 128-bit string and return the complete CSP string
    s := pol.WithNonce(&nonce)
    fmt.Println(nonce)
    // ZNi/o0jlM3cxswKPc+Gr7g

    fmt.Println(s)
    // nonce is base64 encoded 128-bit rand string
    // script-src 'nonce-ZNi/o0jlM3cxswKPc+Gr7g' 'strict-dynamic' 'unsafe-inline' data:
}
```

# Using gin middleware
```golang

import "github.com/jaynzr/cspbuilder"
import "github.com/jaynzr/cspbuilder/csphandler/gincsp"

func main() {
	r := gin.Default()

    // Creates new policy
    pol := cspbuilder.Starter()
    // ... Configures policy

    // If policy directive requires nonce, it will be generated per request
    r.Use(gincsp.ContentSecurityPolicy(pol, false))

    r.GET("/", func(c *gin.Context) {
        nonce := gincsp.Nonce(c)

		c.String(http.StatusOK, `<script nonce="` + nonce + `">doSomething()</script>`)
	})

```

# Using with unrolled/secure middleware
you can use cspbuilder with [secure](https://github.com/unrolled/secure) middleware to create the CSP with optional nonce support.

```golang
import (
    "net/http"

    "github.com/unrolled/secure"
    "github.com/jaynzr/cspbuilder"
    "github.com/jaynzr/cspbuilder/csphandler"
)

var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    nonce := secure.CSPNonce(r.Context())

    w.Write([]byte(`<script nonce="` + nonce + `">doSomething()</script>`))
})

func main() {
    // Creates a new policy
    pol := cspbuilder.New()

    d := pol.New(cspbuilder.Script)
    // add unsafe-line, data:, strict-dynamic, nonce sources to script-src
	d.SourceFlag = cspbuilder.UnsafeInline | cspbuilder.Data | cspbuilder.RequireNonce | cspbuilder.StrictDynamic

    // Builds policy
    pol.Build()

    secureMiddleware := secure.New(secure.Options{
        // ...
        ContentSecurityPolicy: pol.Compiled,
    })

    app := secureMiddleware.Handler(myHandler)
    http.ListenAndServe("127.0.0.1:3000", app)
}
```

# Credits and References

[Content Security Policy (CSP) Quick Reference Guide](https://content-security-policy.com/)


[go-csp-engine](https://github.com/d4l3k/go-csp-engine)
Unit test your CSP rules!

[secure](https://github.com/unrolled/secure)
Secure is an HTTP middleware for Go that facilitates some quick security wins.

[Mitigate cross-site scripting (XSS) with a strict Content Security Policy (CSP)](https://web.dev/strict-csp/)

[CSP Evaluator](https://csp-evaluator.withgoogle.com/)