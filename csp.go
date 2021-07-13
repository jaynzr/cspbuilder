package cspbuilder

import (
	"strings"

	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
)

type hashType int

const (
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

	SHA256 hashType = 256
	SHA384 hashType = 384
	SHA512 hashType = 512
)

type Policy struct {
	dirs      map[string]*Directive
	ReportURI string
	Built     string

	UpgradeInsecureRequests bool

	HasNonce bool
}

type Directive struct {
	Sources []string

	All bool

	// keyword-source
	Self                 bool
	None                 bool
	UnsafeEval           bool
	UnsafeInline         bool
	UnsafeHashes         bool
	UnsafeAllowRedirects bool
	StrictDynamic        bool

	Blob        bool
	Data        bool
	Mediastream bool
	Filesystem  bool

	RequireNonce bool
}

var (
	Self             = &Directive{Self: true}
	None             = &Directive{None: true}
	noncePlaceHolder = "$NONCE" // change using SetNoncePlaceholder()
)

// SetNoncePlaceholder changes the nonce placeholder value $NONCE to your csp middleware's.
func SetNoncePlaceholder(ph string) {
	if ph == "" {
		ph = "$NONCE"
	}
	noncePlaceHolder = ph
}

// New starter policy.
// default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; base-uri 'self';form-action 'self'
// https://content-security-policy.com/
func New() *Policy {
	pol := &Policy{}
	pol.dirs = make(map[string]*Directive)

	pol.dirs[Default] = None
	pol.dirs[BaseURI] = Self
	pol.dirs[Script] = Self
	pol.dirs[Connect] = Self
	pol.dirs[Img] = Self
	pol.dirs[Style] = Self
	pol.dirs[Form] = Self

	return pol
}

func (pp *Policy) With(name string, d *Directive) *Policy {
	pp.dirs[name] = d
	return pp
}

func (pp *Policy) New(name string, sources ...string) *Directive {
	d := &Directive{}
	pp.dirs[name] = d
	if len(sources) > 0 {
		d.Sources = sources
	}
	return d
}

func (pp *Policy) Remove(name string) {
	delete(pp.dirs, name)
}

func (d *Directive) Build(sb *strings.Builder) *strings.Builder {
	if sb == nil {
		sb = &strings.Builder{}
	}

	if d.All {
		sb.WriteString(" *;")
		return sb
	}

	if d.None {
		sb.WriteString(" 'none';")
		return sb
	}

	if d.RequireNonce {
		sb.WriteByte(' ')
		sb.WriteString(noncePlaceHolder)
	}

	if d.StrictDynamic {
		sb.WriteString(" 'strict-dynamic'")
	}

	if d.Self {
		sb.WriteString(" 'self'")
	}

	if d.UnsafeInline {
		sb.WriteString(" 'unsafe-inline'")
	}

	if d.UnsafeEval {
		sb.WriteString(" 'unsafe-eval'")
	}

	if d.UnsafeAllowRedirects {
		sb.WriteString(" 'unsafe-allow-redirects'")
	}

	if d.UnsafeHashes {
		sb.WriteString(" 'unsafe-hashes'")
	}

	if d.Blob {
		sb.WriteString(" blob:")
	}

	if d.Data {
		sb.WriteString(" data:")
	}

	if d.Mediastream {
		sb.WriteString(" mediastream:")
	}

	if d.Filesystem {
		sb.WriteString(" filesystem:")
	}

	if len(d.Sources) > 0 {
		for i := 0; i < len(d.Sources); i++ {
			sb.WriteByte(' ')
			sb.WriteString(d.Sources[i])
		}
	}

	sb.WriteByte(';')

	return sb
}

func (d *Directive) String() string {
	return d.Build(nil).String()
}

// Nonce marks IncludeNonce and StrictDynamic
func (d *Directive) Nonce(req bool, strictDynamic bool) {
	d.RequireNonce = req
	d.StrictDynamic = strictDynamic
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

	sb.WriteString(base64.StdEncoding.EncodeToString(hash[:]))
	sb.WriteByte('\'')
	d.Sources = append(d.Sources, sb.String())

}

// Fetch appends sources to Sources
func (d *Directive) Fetch(sources ...string) {
	d.Sources = append(d.Sources, sources...)
}

// Build policy into string, including NoncePlaceholder when required.
func (pp *Policy) Build() string {
	sb := &strings.Builder{}
	pp.HasNonce = false

	// place default-src first for readability
	if d, ok := pp.dirs[Default]; ok {
		sb.WriteString(Default)
		d.Build(sb)

		pp.HasNonce = pp.HasNonce || d.RequireNonce
	}

	for name, d := range pp.dirs {
		if name == Default {
			continue
		}

		sb.WriteString(name)
		d.Build(sb)

		pp.HasNonce = pp.HasNonce || d.RequireNonce
	}

	if pp.UpgradeInsecureRequests {
		sb.WriteString("upgrade-insecure-requests;")
	}

	if pp.ReportURI != "" {
		sb.WriteString("report-uri ")
		sb.WriteString(pp.ReportURI)
	}

	pp.Built = strings.Trim(sb.String(), " ;")

	return pp.Built
}

// WithNonce returns csp string with nonce
func (pp *Policy) WithNonce(nonce *string) string {
	var (
		_b [32]byte
		b  = _b[:]
	)

	rand.Read(b)
	*nonce = base64.RawStdEncoding.EncodeToString(b)

	if pp.Built == "" {
		pp.Build()
	}

	return strings.ReplaceAll(pp.Built, noncePlaceHolder, "'nonce-"+*nonce+"'")
}

// Map exports directives as map[string]string.
// Does not include nonce source.
// Useful for static middleware like gin-helmet.
func (pp *Policy) Map() map[string]string {
	m := make(map[string]string, len(pp.dirs))

	for k, v := range pp.dirs {
		m[k] = v.String()
	}

	return m
}
