package cpe

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Component is one item extracted from an SBOM: a resolved CPE plus the raw
// name/version for display and for the "confirm the match" UX.
type Component struct {
	Name    string
	Version string
	CPE     CPE
	Source  string // "cpe", "purl", or "derived"
}

// ParseSBOM auto-detects CycloneDX or SPDX (JSON) and returns the components it
// can turn into CPEs. Components with an explicit CPE are exact; those derived
// from a PURL or name+version are best-effort and marked as such so the UI can
// flag lower confidence. Unknown formats return an error rather than silently
// yielding nothing.
func ParseSBOM(data []byte) ([]Component, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("SBOM is not valid JSON: %w", err)
	}
	switch {
	case probe["bomFormat"] != nil || probe["components"] != nil:
		return parseCycloneDX(data)
	case probe["spdxVersion"] != nil || probe["packages"] != nil:
		return parseSPDX(data)
	}
	return nil, fmt.Errorf("unrecognised SBOM format (expected CycloneDX or SPDX JSON)")
}

type cyclonedx struct {
	Components []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		CPE     string `json:"cpe"`
		PURL    string `json:"purl"`
	} `json:"components"`
}

func parseCycloneDX(data []byte) ([]Component, error) {
	var doc cyclonedx
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("invalid CycloneDX: %w", err)
	}
	var out []Component
	for _, c := range doc.Components {
		if comp, ok := componentFrom(c.Name, c.Version, c.CPE, c.PURL); ok {
			out = append(out, comp)
		}
	}
	return out, nil
}

type spdx struct {
	Packages []struct {
		Name         string `json:"name"`
		VersionInfo  string `json:"versionInfo"`
		ExternalRefs []struct {
			ReferenceType    string `json:"referenceType"`
			ReferenceLocator string `json:"referenceLocator"`
		} `json:"externalRefs"`
	} `json:"packages"`
}

func parseSPDX(data []byte) ([]Component, error) {
	var doc spdx
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("invalid SPDX: %w", err)
	}
	var out []Component
	for _, p := range doc.Packages {
		cpeStr, purlStr := "", ""
		for _, ref := range p.ExternalRefs {
			switch ref.ReferenceType {
			case "cpe23Type":
				cpeStr = ref.ReferenceLocator
			case "purl":
				purlStr = ref.ReferenceLocator
			}
		}
		if comp, ok := componentFrom(p.Name, p.VersionInfo, cpeStr, purlStr); ok {
			out = append(out, comp)
		}
	}
	return out, nil
}

// componentFrom builds a Component from whatever identifiers a package carried,
// in order of confidence: explicit CPE > PURL-derived > name+version-derived.
func componentFrom(name, version, cpeStr, purl string) (Component, bool) {
	if cpeStr != "" {
		if c, err := Parse(cpeStr); err == nil {
			return Component{Name: name, Version: version, CPE: c, Source: "cpe"}, true
		}
	}
	if purl != "" {
		if pn, pv, ok := parsePURL(purl); ok {
			if c, err := FromProductVersion(pn, firstNonEmpty(version, pv)); err == nil {
				return Component{Name: name, Version: firstNonEmpty(version, pv), CPE: c, Source: "purl"}, true
			}
		}
	}
	if name != "" {
		if c, err := FromProductVersion(name, version); err == nil {
			return Component{Name: name, Version: version, CPE: c, Source: "derived"}, true
		}
	}
	return Component{}, false
}

// parsePURL extracts the package name and version from a Package URL:
//
//	pkg:type/namespace/name@version?qualifiers#subpath
func parsePURL(purl string) (name, version string, ok bool) {
	if !strings.HasPrefix(purl, "pkg:") {
		return "", "", false
	}
	body := purl[len("pkg:"):]
	// Strip qualifiers and subpath.
	if i := strings.IndexAny(body, "?#"); i >= 0 {
		body = body[:i]
	}
	if at := strings.LastIndex(body, "@"); at >= 0 {
		version = body[at+1:]
		body = body[:at]
	}
	segs := strings.Split(body, "/")
	if len(segs) < 2 {
		return "", "", false
	}
	name = segs[len(segs)-1] // last path segment is the name
	if name == "" {
		return "", "", false
	}
	return name, version, true
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
