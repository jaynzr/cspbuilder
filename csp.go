// Package cspbuilder provides helper funcs to create Content Security Policy
package cspbuilder

import (
	"strings"

	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
)

type hashType uint16
type sourceFlag uint32

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

	SHA256 hashType = 256
	SHA384 hashType = 384
	SHA512 hashType = 512
)

// Sources flags to apply to Directive.SourceFlag
const (
	None sourceFlag = 0
	All  sourceFlag = 1 << iota
	Self

	// Nonce means policy must run WithNonce()
	Nonce
	StrictDynamic

	UnsafeEval
	UnsafeInline
	UnsafeHashes
	UnsafeAllowRedirects

	Blob
	Data
	Mediastream
	Filesystem

	ReportSample
)

var (
	SelfDirective = &Directive{SourceFlag: Self}
	NoneDirective = &Directive{SourceFlag: None}

	src = map[sourceFlag]string{
		None:                 " 'none';",
		All:                  " *;",
		Self:                 " 'self'",
		UnsafeEval:           " 'unsafe-eval'",
		UnsafeInline:         " 'unsafe-inline'",
		UnsafeHashes:         " 'unsafe-hashes'",
		UnsafeAllowRedirects: " 'unsafe-allow-redirects'",
		StrictDynamic:        " 'strict-dynamic'",

		Blob:        " blob:",
		Data:        " data:",
		Mediastream: " mediastream:",
		Filesystem:  " filesystem:",

		// nonce placeholder in Compiled string. Change using SetNoncePlaceholder()
		Nonce: " $NONCE",

		ReportSample: "report-sample",
	}
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
	Sources    []string
	SourceFlag sourceFlag
}

// SetNoncePlaceholder changes the nonce placeholder value $NONCE to your csp middleware's.
func SetNoncePlaceholder(ph string) {
	if ph == "" {
		ph = "$NONCE"
	}
	// noncePlaceHolder = ph
	src[Nonce] = " " + ph
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
	if pp.dirs ==  nil {
		pp.dirs = make(map[string]*Directive)
	}

	pp.dirs[name] = d
	return pp
}

// New directive added to policy.
// Existing directive is replaced.
func (pp *Policy) New(name string, sources ...string) *Directive {
	if pp.dirs ==  nil {
		pp.dirs = make(map[string]*Directive)
	}

	d := &Directive{}
	pp.dirs[name] = d
	if len(sources) > 0 {
		d.Sources = sources
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
	if sb == nil {
		sb = &strings.Builder{}
	}

	if (d.SourceFlag == All) || (d.SourceFlag == None && len(d.Sources) == 0) {
		s := src[d.SourceFlag]

		sb.WriteString(s)

		return
	}

	for f := Self; f <= d.SourceFlag; f = f << 1 {
		if ff := f & d.SourceFlag; ff != 0 {
			if s, ok := src[ff]; ok {
				sb.WriteString(s)
			}
		}
	}

	for i := 0; i < len(d.Sources); i++ {
		s := d.Sources[i]

		sb.WriteByte(' ')
		sb.WriteString(s)

	}

	sb.WriteByte(';')
}

func (d *Directive) String() string {
	var sb strings.Builder
	d.write(&sb)

	return sb.String()
}

// Hash the source and appends to Sources
func (d *Directive) Hash(ht hashType, source string) {
	var (
		hash []byte
		sb   strings.Builder
	)
	sb.WriteString("'sha")

	switch ht {
	case SHA256:
		sb.WriteString("256-")
		h := sha256.Sum256([]byte(source))
		hash = h[:]
	case SHA384:
		sb.WriteString("384-")
		h := sha512.Sum384([]byte(source))
		hash = h[:]
	case SHA512:
		sb.WriteString("512-")
		h := sha512.Sum512([]byte(source))
		hash = h[:]
	}

	sb.WriteString(base64.StdEncoding.EncodeToString(hash))
	sb.WriteByte('\'')
	d.Sources = append(d.Sources, sb.String())

}

// Fetch appends sources to Sources
func (d *Directive) Fetch(sources ...string) {
	d.Sources = append(d.Sources, sources...)
}

// Build policy into string
func (pp *Policy) Build() string {
	var (
		sb = &strings.Builder{}
	)
	pp.RequireNonce = false

	// place default-src first for readability
	if d, ok := pp.dirs[Default]; ok {
		sb.WriteString(Default)
		d.write(sb)

		pp.RequireNonce = pp.RequireNonce || (d.SourceFlag&Nonce) != 0
	}

	for name, d := range pp.dirs {
		if name == Default {
			continue
		}

		sb.WriteString(name)
		d.write(sb)

		pp.RequireNonce = pp.RequireNonce || (d.SourceFlag&Nonce) != 0
	}

	if pp.UpgradeInsecureRequests {
		sb.WriteString(upgradeInsecureRequests)
	}

	if pp.ReportURI != "" {
		sb.WriteString(reportUri)
		sb.WriteString(pp.ReportURI)
	}

	pp.Compiled = sb.String()
	if len(pp.Compiled) > 0 && pp.Compiled[len(pp.Compiled)-1:] == ";" {
		pp.Compiled = pp.Compiled[:len(pp.Compiled)-1]
	}

	return pp.Compiled
}

// WithNonce returns csp string with nonce
func (pp *Policy) WithNonce(nonce *string) string {
	var (
		_b [16]byte
		b  = _b[:]
	)

	if _, err := rand.Read(b); err != nil {
		panic("cspbuilder rand read failed")
	}
	*nonce = base64.RawStdEncoding.EncodeToString(b)

	if pp.Compiled == "" {
		pp.Build()
	}

	return strings.ReplaceAll(pp.Compiled, src[Nonce], " 'nonce-"+*nonce+"'")
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
