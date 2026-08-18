// Package patchlight is the fourth Sentinel product: CVE prioritisation. It
// matches CVEs to a user's real inventory (by CPE, via NVD) and ranks them by
// whether they're actually being exploited (CISA KEV), likely to be (FIRST
// EPSS), and how severe (CVSS) — so the dashboard shows the handful that matter,
// not the firehose.
//
// It is poll-driven and reuses the whole Sentinel Core unchanged. The one new
// idea is the Intel seam: the Collector depends on an Intel interface (CVEs for
// a CPE, already enriched), so the priority logic is pure and fully testable
// offline, while the live implementation wires the NVD/KEV/EPSS feeds behind it
// with shared, cached enrichment.
package patchlight

import (
	"context"

	"github.com/nizartuanku/patchlight/core"
	"github.com/nizartuanku/patchlight/cpe"
)

// ModuleID is the module id used across findings and the scheduler.
const ModuleID = "patchlight"

// Vuln is a CVE affecting one inventory item, already enriched with the three
// prioritisation signals. The Intel implementation fills it; the Collector only
// ranks and renders it.
type Vuln struct {
	ID           string  `json:"id"`            // CVE-2024-3094
	Summary      string  `json:"summary"`       // one-line description
	CVSS         float64 `json:"cvss"`          // base score 0..10 (0 = unknown)
	CVSSVector   string  `json:"cvss_vector"`   //
	EPSS         float64 `json:"epss"`          // exploit probability 0..1
	KEV          bool    `json:"kev"`           // on CISA Known Exploited list
	KEVDateAdded string  `json:"kev_date_added"` //
	FixedVersion string  `json:"fixed_version"` // if NVD/advisory gives one
	MatchedCPE   string  `json:"matched_cpe"`   // the CPE NVD matched
	VersionRange string  `json:"version_range"` // human hint, e.g. "< 1.24.1"
	URL          string  `json:"url"`           // canonical CVE link
}

// Priority buckets, most urgent first. They map to core severities but carry the
// product's own vocabulary so the "why" is explicit in every finding.
type Priority string

const (
	P1 Priority = "P1" // on CISA KEV — confirmed exploited AND affects you
	P2 Priority = "P2" // high EPSS, or critical CVSS with real EPSS
	P3 Priority = "P3" // meaningful CVSS, low EPSS — plan it
	P4 Priority = "P4" // matched but low severity / low exploitation signal
)

// Rank applies the priority model. It is a pure function — the heart of the
// product — so it is trivially and exhaustively testable.
func Rank(v Vuln) (Priority, core.Severity) {
	switch {
	case v.KEV:
		return P1, core.SeverityCritical
	case v.EPSS >= 0.5 || (v.CVSS >= 9.0 && v.EPSS >= 0.1):
		return P2, core.SeverityHigh
	case v.CVSS >= 7.0:
		return P3, core.SeverityMedium
	default:
		return P4, core.SeverityLow
	}
}

// Intel returns the CVEs affecting a CPE, already enriched with KEV/EPSS/CVSS.
// The Collector depends only on this; the live wiring (nvd+kev+epss with shared
// caching) implements it, and tests inject a fake.
type Intel interface {
	CVEsFor(ctx context.Context, target cpe.CPE) ([]Vuln, error)
}

// vulnFinding renders one enriched CVE as a core.Finding. Target MUST equal the
// scanned canonical (the CPE string) so the reconcile engine groups it; the
// fingerprint embeds the CVE id so each CVE is its own finding and new ones
// surface via the daily diff while patched ones auto-resolve.
func vulnFinding(targetCPE cpe.CPE, v Vuln) core.Finding {
	prio, sev := Rank(v)
	label := targetCPE.Label()

	remediation := "Upgrade to a fixed release, or apply the advisory's mitigation — no fixed version is listed yet."
	if v.FixedVersion != "" {
		remediation = "Patch " + label + " to ≥ " + v.FixedVersion + "."
	}

	why := string(prio) + " · "
	if v.KEV {
		why += "on CISA KEV"
		if v.KEVDateAdded != "" {
			why += " (" + v.KEVDateAdded + ")"
		}
		why += " · "
	}
	why += "EPSS " + formatProb(v.EPSS) + " · CVSS " + formatScore(v.CVSS)

	return core.Finding{
		Fingerprint: core.Fingerprint(ModuleID, targetCPE.Canonical(), "cve", v.ID),
		Target:      targetCPE.Canonical(),
		Check:       "cve",
		Title:       v.ID + " affects " + label + " — " + why,
		Severity:    sev,
		Remediation: remediation,
		Evidence: map[string]any{
			"cve":           v.ID,
			"priority":      string(prio),
			"cvss":          v.CVSS,
			"cvss_vector":   v.CVSSVector,
			"epss":          v.EPSS,
			"kev":           v.KEV,
			"kev_date":      v.KEVDateAdded,
			"fixed_version": v.FixedVersion,
			"matched_cpe":   v.MatchedCPE,
			"version_range": v.VersionRange,
			"summary":       v.Summary,
			"url":           v.URL,
		},
	}
}
