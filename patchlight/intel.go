package patchlight

import (
	"context"

	"github.com/nizartuanku/patchlight/cpe"
	"github.com/nizartuanku/patchlight/epss"
	"github.com/nizartuanku/patchlight/kev"
	"github.com/nizartuanku/patchlight/nvd"
)

// LiveIntel is the production Intel: it asks NVD which CVEs affect a CPE, then
// enriches each with CISA KEV membership and FIRST EPSS probability. KEV and
// EPSS are best-effort — if a feed is unavailable the CVEs still surface with
// their CVSS, just without that enrichment, rather than the whole scan failing.
// The providers cache internally, so a CVE affecting many inventory items is
// enriched once, not once per item.
type LiveIntel struct {
	NVD  *nvd.Client
	KEV  *kev.Provider
	EPSS *epss.Provider
}

// CVEsFor implements Intel.
func (l *LiveIntel) CVEsFor(ctx context.Context, target cpe.CPE) ([]Vuln, error) {
	raw, err := l.NVD.CVEsFor(ctx, target)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}

	ids := make([]string, 0, len(raw))
	for _, c := range raw {
		ids = append(ids, c.ID)
	}

	var cat kev.Catalog
	if l.KEV != nil {
		cat, _ = l.KEV.Get(ctx) // tolerate: no KEV enrichment on error
	}
	var scores map[string]float64
	if l.EPSS != nil {
		scores, _ = l.EPSS.Scores(ctx, ids) // tolerate: EPSS defaults to 0
	}

	out := make([]Vuln, 0, len(raw))
	for _, c := range raw {
		out = append(out, Vuln{
			ID:           c.ID,
			Summary:      c.Summary,
			CVSS:         c.CVSS,
			CVSSVector:   c.CVSSVector,
			EPSS:         scores[c.ID],
			KEV:          cat.Has(c.ID),
			KEVDateAdded: cat.DateAdded(c.ID),
			FixedVersion: c.FixedVersion,
			MatchedCPE:   c.MatchedCPE,
			VersionRange: c.VersionRange,
			URL:          c.URL,
		})
	}
	return out, nil
}
