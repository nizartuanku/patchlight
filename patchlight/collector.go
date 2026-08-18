package patchlight

import (
	"context"
	"strconv"
	"time"

	"github.com/nizartuanku/patchlight/core"
	"github.com/nizartuanku/patchlight/cpe"
)

// Collector is Patchlight's poll-driven engine. Each target is one inventory
// item (a CPE); Collect asks Intel for the CVEs affecting it, ranks each, and
// emits a finding per relevant CVE. The reconcile engine then gives the daily
// diff (new CVE / new KEV entry → new finding) and auto-resolve (patched → the
// CPE no longer matches → finding resolves) for free.
type Collector struct {
	intel Intel
}

// New builds the collector over an Intel source (live NVD/KEV/EPSS wiring, or a
// fake in tests).
func New(intel Intel) *Collector { return &Collector{intel: intel} }

// Describe returns module metadata. Vuln intel changes daily, not by the
// minute, so the default interval is generous and polite to NVD.
func (c *Collector) Describe() core.ModuleInfo {
	return core.ModuleInfo{
		ID:              ModuleID,
		Name:            "Patchlight",
		Version:         "0.1.0",
		TargetKind:      "cpe",
		DefaultInterval: 12 * time.Hour,
		ResolveAfter:    1,
	}
}

// ValidateTarget accepts a CPE 2.3 formatted string (the canonical inventory
// key). Free-text product+version and SBOM components are resolved to CPEs by
// the Patchlight console before being registered, so by the time a target
// reaches the scheduler it is always a CPE.
func (c *Collector) ValidateTarget(raw string) (core.Target, error) {
	parsed, err := cpe.Parse(raw)
	if err != nil {
		return core.Target{}, &core.IngestError{Field: "target", Reason: err.Error()}
	}
	return core.Target{Raw: raw, Canonical: parsed.Canonical(), Meta: map[string]string{"label": parsed.Label()}}, nil
}

// Collect matches CVEs to the target CPE and emits a ranked finding per CVE. An
// item with no affecting CVEs returns an empty slice ("checked, all clear").
func (c *Collector) Collect(ctx context.Context, t core.Target) ([]core.Finding, error) {
	target, err := cpe.Parse(t.Canonical)
	if err != nil {
		return nil, err
	}
	vulns, err := c.intel.CVEsFor(ctx, target)
	if err != nil {
		return nil, err
	}
	out := make([]core.Finding, 0, len(vulns))
	for _, v := range vulns {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if v.ID == "" {
			continue
		}
		out = append(out, vulnFinding(target, v))
	}
	return out, nil
}

// Diff defers to the core's fingerprint-based diff (new-since-last is exactly
// reconcile's NewlyOpen).
func (c *Collector) Diff(previous, current []core.Finding) []core.Change { return nil }

// --- formatting helpers -----------------------------------------------------

func formatScore(f float64) string {
	if f <= 0 {
		return "—"
	}
	return strconv.FormatFloat(f, 'f', 1, 64)
}

func formatProb(f float64) string {
	if f < 0 {
		f = 0
	}
	return strconv.FormatFloat(f, 'f', 2, 64)
}
