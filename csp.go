// Package cspbuilder provides helper funcs to create Content Security Policy
package cspbuilder

import (
	"strings"

	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
)

type HashType uint16

const (
	// csp v1
	Default = "default-src"
	Connect = "connect-src"
	Font    = "font-src"
	Frame   = "frame-src"
	Img     = "img-src"
	Media   = "media-src"
	Object  = "object-src"
	Sandbox = "sandbox"
	Script  = "script-src"
	Style   = "style-src"

	// csp v2
	BaseURI        = "base-uri"
	Child          = "child-src"
	FrameAncestors = "frame-ancestors"
	Plugin         = "plugin-types"
	Form           = "form-action"

	// csp v3
	TrustedTypes           = "trusted-types"
	RequireTrustedTypesFor = "require-trusted-types-for"
	StyleAttr              = "style-src-attr"
	StyleElem              = "style-src-elem"
	ScriptAttr             = "script-src-attr"
	ScriptElem             = "script-src-elem"
	Worker                 = "worker-src"
	NavigateTo             = "navigate-to"
	Prefetch               = "prefetch-src"
	Manifest               = "manifest-src"
	ReportTo               = "report-to"

	upgradeInsecureRequests = "upgrade-insecure-requests;"
	reportUri               = "report-uri "

	SHA256 HashType = 256
	SHA384 HashType = 384
	SHA512 HashType = 512
)

// Keyword sources
const (
	None = "'none'"
	All  = "*"
	Self = "'self'"

	StrictDynamic = "'strict-dynamic'"

	UnsafeEval           = "'unsafe-eval'"
	UnsafeInline         = "'unsafe-inline'"
	UnsafeHashes         = "'unsafe-hashes'"
	UnsafeAllowRedirects = "'unsafe-allow-redirects'"
	ReportSample         = "'report-sample'"
	TrustedScript        = "'script'"

	Blob        = "blob:"
	Data        = "data:"
	Mediastream = "mediastream:"
	Filesystem  = "filesystem:"
)

var (
	SelfDirective = &Directive{sources: []string{Self}}
	NoneDirective = &Directive{sources: []string{None}}

	// Nonce means policy must run WithNonce()
	Nonce = "$NONCE"
)

type Policy struct {
	dirs map[string]*Directive

	// ReportURI appends "report-uri <string>"
	ReportURI string

	// Compiled policy after running Build()
	Compiled string

	// UpgradeInsecureRequests appends "'upgrade-insecure-requests'"
	UpgradeInsecureRequests bool

	// RequireNonce is set if policy must run WithNonce()
	RequireNonce bool
}

type Directive struct {
	sources []string
	// SourceFlag sourceFlag
	requireNonce bool
}

// SetNoncePlaceholder changes the nonce placeholder value $NONCE to your csp middleware's.
func SetNoncePlaceholder(ph string) {
	if ph == "" {
		ph = "$NONCE"
	}
	Nonce = ph
}

// Starter creates new policy with sensible defaults
// default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; base-uri 'self';form-action 'self'
// https://content-security-policy.com/
func Starter() *Policy {
	pol := &Policy{}
	pol.dirs = make(map[string]*Directive)

	pol.dirs[Default] = NoneDirective
	pol.dirs[BaseURI] = SelfDirective
	pol.dirs[Script] = SelfDirective
	pol.dirs[Connect] = SelfDirective
	pol.dirs[Img] = SelfDirective
	pol.dirs[Style] = SelfDirective
	pol.dirs[Form] = SelfDirective

	return pol
}

// New creates blank policy
func New() *Policy {
	pol := &Policy{}
	pol.dirs = make(map[string]*Directive)

	return pol
}

// With adds directive to policy.
// Existing directive is replaced.
func (pp *Policy) With(name string, d *Directive) *Policy {
	if pp.dirs == nil {
		pp.dirs = make(map[string]*Directive)
	}

	pp.dirs[name] = d
	return pp
}

// New directive added to policy.
// Existing directive is replaced.
func (pp *Policy) New(name string, sources ...string) *Directive {
	if pp.dirs == nil {
		pp.dirs = make(map[string]*Directive)
	}

	d := &Directive{}
	pp.dirs[name] = d
	if len(sources) > 0 {
		d.Add(sources...)
	}
	return d
}

// Remove directive from policy
func (pp *Policy) Remove(name string) {
	delete(pp.dirs, name)
}

// write directive.
// Used by Policy.Build()
func (d *Directive) write(sb *strings.Builder) {
	n := 1
	if sb == nil {
		sb = &strings.Builder{}
	}

	if len(d.sources) > 0 {
		n = len(d.sources) - 1
		for i := 0; i < len(d.sources); i++ {
			n += len(d.sources[i])
		}

		sb.Grow(n + 1)
		sb.WriteString(d.sources[0])

		for i := 1; i < len(d.sources); i++ {
			sb.WriteByte(' ')
			sb.WriteString(d.sources[i])
		}
	} else {
		sb.WriteString(None)
	}
}

func (d *Directive) String() string {
	var sb strings.Builder
	d.write(&sb)

	return sb.String()
}

// Hash the source and appends to Sources
func (d *Directive) Hash(ht HashType, source string) {
	d.sources = append(d.sources, hash(ht, source))
}

func hash(ht HashType, source string) string {
	var (
		hash []byte
		sb   strings.Builder
	)

	switch ht {
	case SHA256:
		sb.Grow(53)
		sb.WriteString("'sha256-")
		h := sha256.Sum256([]byte(source))
		hash = h[:]
	case SHA384:
		sb.Grow(73)
		sb.WriteString("'sha384-")
		h := sha512.Sum384([]byte(source))
		hash = h[:]
	case SHA512:
		sb.Grow(97)
		sb.WriteString("'sha512-")
		h := sha512.Sum512([]byte(source))
		hash = h[:]
	default:
		panic("invalid hashType")
	}

	sb.WriteString(base64.StdEncoding.EncodeToString(hash))
	sb.WriteByte('\'')
	return sb.String()
}

// Add appends sources to Sources
func (d *Directive) Add(sources ...string) {
	if d == SelfDirective || d == NoneDirective {
		panic("immutable directive")
	}
	if d.sources == nil {
		d.sources = make([]string, 0, len(sources))
	}

	for _, v := range sources {
		if v == Nonce {
			d.requireNonce = true
			break
		}
	}
	d.sources = append(d.sources, sources...)
}

// Build policy into string
func (pp *Policy) Build() string {
	pp.Compiled = pp.MergeBuild(nil)
	return pp.Compiled
}

func (pp *Policy) MergeBuild(dirs map[string]*Directive) string {
	var (
		sb   = &strings.Builder{}
		size int
	)
	pp.RequireNonce = false

	if pp.UpgradeInsecureRequests {
		size += len(upgradeInsecureRequests)
	}

	if pp.ReportURI != "" {
		size += len(reportUri) + len(pp.ReportURI)
	}

	sb.Grow(size)

	pp.writeDirs(sb, dirs)

	if pp.UpgradeInsecureRequests {
		sb.WriteString(upgradeInsecureRequests)
	}

	if pp.ReportURI != "" {
		sb.WriteString(reportUri)
		sb.WriteString(pp.ReportURI)
	}

	compiled := sb.String()
	if len(compiled) > 0 && compiled[len(compiled)-1:] == ";" {
		compiled = compiled[:len(compiled)-1]
	}

	return compiled
}

func (pp *Policy) writeDirs(sb *strings.Builder, dirs map[string]*Directive) {

	// place default-src first for readability
	/* if d, ok := pp.dirs[Default]; ok {
		sb.WriteString(Default)
		sb.WriteByte(' ')
		d.write(sb)

		if dirs != nil {
			if d, ok := dirs[Default]; ok {
				sb.WriteByte(' ')
				d.write(sb)

				pp.RequireNonce = pp.RequireNonce || d.requireNonce
			}
		}

		sb.WriteByte(';')
		pp.RequireNonce = pp.RequireNonce || d.requireNonce
	} */

	for name, d := range pp.dirs {
		/* if name == Default {
			continue
		} */

		sb.WriteString(name)
		sb.WriteByte(' ')
		d.write(sb)
		pp.RequireNonce = pp.RequireNonce || d.requireNonce

		if dirs != nil {
			if d, ok := dirs[name]; ok {
				sb.WriteByte(' ')
				d.write(sb)

				pp.RequireNonce = pp.RequireNonce || d.requireNonce
			}
		}

		sb.WriteByte(';')
	}
}

// WithNonce returns csp string with nonce
func (pp *Policy) WithNonce(nonce *string) string {
	var (
		_b [16]byte
		b  = _b[:]
	)
	if pp.Compiled == "" {
		pp.Build()
	}

	if !pp.RequireNonce {
		return pp.Compiled
	}

	if _, err := rand.Read(b); err != nil {
		panic("cspbuilder rand read failed")
	}
	*nonce = base64.RawURLEncoding.EncodeToString(b)

	return strings.ReplaceAll(pp.Compiled, Nonce, "'nonce-"+*nonce+"'")
}

// Map exports directives as map[string]string.
// Does not include nonce source.
// Meant for middleware like gin-helmet that can only emit static csp strings
func (pp *Policy) Map() map[string]string {
	m := make(map[string]string, len(pp.dirs))

	for k, v := range pp.dirs {
		m[k] = v.String()
	}

	return m
}
