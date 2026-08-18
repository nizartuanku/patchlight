// Package cpe is Patchlight's inventory primitive: a parsed CPE 2.3 name plus
// the plumbing to get one from what a user actually types or uploads. It knows
// nothing about CVEs or feeds — matching CVEs to a CPE is NVD's job (the nvd
// package asks NVD by CPE), so this package stays a small, pure, well-tested
// value type and an SBOM reader.
package cpe

import (
	"fmt"
	"strings"
)

// CPE is a parsed CPE 2.3 formatted-string name. Only the fields Patchlight
// reasons about are named; the rest are kept so String() round-trips.
//
// Formatted string layout (13 colon-separated fields):
//
//	cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
type CPE struct {
	Part      string // a (application), o (os), h (hardware)
	Vendor    string
	Product   string
	Version   string
	Update    string
	Edition   string
	Language  string
	SWEdition string
	TargetSW  string
	TargetHW  string
	Other     string
}

// Parse reads a CPE 2.3 formatted string. It is lenient about a trailing set of
// "*" fields (a common short form) but strict about the cpe:2.3 prefix and the
// part field, so garbage doesn't silently become a target.
func Parse(s string) (CPE, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "cpe:2.3:") {
		return CPE{}, fmt.Errorf("not a CPE 2.3 name (must start with cpe:2.3:): %q", s)
	}
	fields := splitEscaped(s)
	// fields[0]="cpe", fields[1]="2.3", then up to 11 attributes.
	if len(fields) < 5 {
		return CPE{}, fmt.Errorf("CPE has too few fields: %q", s)
	}
	get := func(i int) string {
		if i < len(fields) {
			return unbind(fields[i])
		}
		return "*"
	}
	part := get(2)
	switch part {
	case "a", "o", "h":
	default:
		return CPE{}, fmt.Errorf("invalid CPE part %q (want a|o|h): %q", part, s)
	}
	c := CPE{
		Part: part, Vendor: get(3), Product: get(4), Version: get(5),
		Update: get(6), Edition: get(7), Language: get(8),
		SWEdition: get(9), TargetSW: get(10), TargetHW: get(11), Other: get(12),
	}
	if c.Product == "" || c.Product == "*" {
		return CPE{}, fmt.Errorf("CPE has no product: %q", s)
	}
	return c, nil
}

// String renders the canonical 13-field CPE 2.3 formatted string.
func (c CPE) String() string {
	f := func(v string) string {
		if v == "" {
			return "*"
		}
		return bind(v)
	}
	return strings.Join([]string{
		"cpe", "2.3", f(c.Part), f(c.Vendor), f(c.Product), f(c.Version),
		f(c.Update), f(c.Edition), f(c.Language), f(c.SWEdition),
		f(c.TargetSW), f(c.TargetHW), f(c.Other),
	}, ":")
}

// Canonical is the String form, used as the scheduler target key.
func (c CPE) Canonical() string { return c.String() }

// Label is a short human name for dashboards: "vendor product version".
func (c CPE) Label() string {
	parts := []string{}
	if c.Vendor != "" && c.Vendor != "*" && c.Vendor != c.Product {
		parts = append(parts, c.Vendor)
	}
	parts = append(parts, c.Product)
	if c.Version != "" && c.Version != "*" && c.Version != "-" {
		parts = append(parts, c.Version)
	}
	return strings.Join(parts, " ")
}

// FromProductVersion builds a best-effort application CPE from a free-text
// product and version (vendor left as a wildcard so NVD's match logic can pair
// it). It is the fallback when no NVD dictionary resolution is available; the
// resolver in the nvd package produces a precise cpeName when it can.
func FromProductVersion(product, version string) (CPE, error) {
	product = normalizeToken(product)
	if product == "" {
		return CPE{}, fmt.Errorf("empty product")
	}
	v := normalizeToken(version)
	if v == "" {
		v = "*"
	}
	return CPE{Part: "a", Vendor: "*", Product: product, Version: v}, nil
}

func normalizeToken(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.ReplaceAll(s, " ", "_")
	return s
}

// --- CPE formatted-string binding helpers ---------------------------------

// splitEscaped splits on ':' but respects backslash-escaped colons.
func splitEscaped(s string) []string {
	var out []string
	var cur strings.Builder
	esc := false
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\':
			cur.WriteRune(r)
			esc = true
		case r == ':':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	out = append(out, cur.String())
	return out
}

// bind escapes the characters that are special in a CPE formatted string.
func bind(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `:`, `\:`, `?`, `\?`, `*`, `\*`)
	// Preserve legitimate wildcard/NA tokens unescaped.
	if v == "*" || v == "-" {
		return v
	}
	return r.Replace(v)
}

// unbind reverses bind's escaping for the fields we store.
func unbind(v string) string {
	r := strings.NewReplacer(`\\`, `\`, `\:`, `:`, `\?`, `?`, `\*`, `*`)
	return r.Replace(v)
}
