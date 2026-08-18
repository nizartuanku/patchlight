package patchlight

import (
	"context"
	"strings"
	"testing"

	"github.com/nizartuanku/patchlight/core"
	"github.com/nizartuanku/patchlight/cpe"
	"github.com/nizartuanku/patchlight/epss"
	"github.com/nizartuanku/patchlight/kev"
	"github.com/nizartuanku/patchlight/nvd"
	"github.com/nizartuanku/patchlight/store"
)

func TestRank(t *testing.T) {
	cases := []struct {
		name string
		v    Vuln
		want Priority
		sev  core.Severity
	}{
		{"kev beats everything", Vuln{KEV: true, CVSS: 4.0, EPSS: 0.01}, P1, core.SeverityCritical},
		{"high epss", Vuln{EPSS: 0.6, CVSS: 5.0}, P2, core.SeverityHigh},
		{"critical cvss with some epss", Vuln{CVSS: 9.8, EPSS: 0.2}, P2, core.SeverityHigh},
		{"high cvss low epss", Vuln{CVSS: 7.5, EPSS: 0.02}, P3, core.SeverityMedium},
		{"low signal", Vuln{CVSS: 4.0, EPSS: 0.01}, P4, core.SeverityLow},
	}
	for _, c := range cases {
		p, s := Rank(c.v)
		if p != c.want || s != c.sev {
			t.Errorf("%s: got %s/%s want %s/%s", c.name, p, s, c.want, c.sev)
		}
	}
}

type fakeIntel struct{ vulns []Vuln }

func (f fakeIntel) CVEsFor(_ context.Context, _ cpe.CPE) ([]Vuln, error) { return f.vulns, nil }

func TestCollectorEmitsRankedFindings(t *testing.T) {
	target := "cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*"
	intel := fakeIntel{vulns: []Vuln{
		{ID: "CVE-2024-0001", KEV: true, KEVDateAdded: "2026-07-02", CVSS: 8.1, EPSS: 0.87, FixedVersion: "3.0.12"},
		{ID: "CVE-2024-0002", CVSS: 5.0, EPSS: 0.01},
	}}
	c := New(intel)
	fs, err := c.Collect(context.Background(), core.Target{Canonical: target})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d", len(fs))
	}
	var p1 core.Finding
	for _, f := range fs {
		if f.Target != target {
			t.Errorf("finding target %q must equal scan canonical %q", f.Target, target)
		}
		if f.Remediation == "" {
			t.Errorf("finding %s has no remediation", f.Evidence["cve"])
		}
		if f.Evidence["cve"] == "CVE-2024-0001" {
			p1 = f
		}
	}
	if p1.Severity != core.SeverityCritical {
		t.Errorf("KEV finding severity = %s, want critical", p1.Severity)
	}
	if !strings.Contains(p1.Title, "P1") || !strings.Contains(p1.Title, "on CISA KEV") {
		t.Errorf("title should explain priority: %q", p1.Title)
	}
	if !strings.Contains(p1.Remediation, "3.0.12") {
		t.Errorf("remediation should name the fixed version: %q", p1.Remediation)
	}
}

// Patching an item (its CVE no longer returned) auto-resolves the finding.
func TestPatchedCVEAutoResolves(t *testing.T) {
	target := "cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*"
	fs := store.NewMemStore()
	eng := store.NewEngine(fs)

	c := New(fakeIntel{vulns: []Vuln{{ID: "CVE-2024-0001", KEV: true, CVSS: 8.1}}})
	cur, _ := c.Collect(context.Background(), core.Target{Canonical: target})
	res, _ := eng.Reconcile(c.Describe(), target, cur)
	if len(res.NewlyOpen) != 1 {
		t.Fatalf("want 1 newly open, got %d", len(res.NewlyOpen))
	}
	// Next scan: patched, no CVEs.
	c2 := New(fakeIntel{vulns: nil})
	cur2, _ := c2.Collect(context.Background(), core.Target{Canonical: target})
	res2, _ := eng.Reconcile(c2.Describe(), target, cur2)
	if len(res2.Resolved) != 1 {
		t.Fatalf("want 1 resolved after patch, got %d", len(res2.Resolved))
	}
}

// End-to-end feed pipeline with injected fetchers — no network.
func TestLiveIntelEnrichesFromFeeds(t *testing.T) {
	nvdJSON := `{"vulnerabilities":[{"cve":{
	  "id":"CVE-2024-0001",
	  "descriptions":[{"lang":"en","value":"a serious bug"}],
	  "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":8.1,"vectorString":"CVSS:3.1/AV:N"}}]},
	  "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*","versionEndExcluding":"3.0.12"}]}]}],
	  "references":[{"url":"https://example.test"}]
	}}]}`
	kevJSON := `{"vulnerabilities":[{"cveID":"CVE-2024-0001","dateAdded":"2026-07-02"}]}`
	epssJSON := `{"data":[{"cve":"CVE-2024-0001","epss":"0.87"}]}`

	fetch := func(_ context.Context, url string) ([]byte, error) {
		switch {
		case strings.Contains(url, "nvdcve"):
			return []byte(nvdJSON), nil
		case strings.Contains(url, "kevfeed"):
			return []byte(kevJSON), nil
		case strings.Contains(url, "epssapi"):
			return []byte(epssJSON), nil
		}
		return []byte(`{}`), nil
	}

	intel := &LiveIntel{
		NVD:  &nvd.Client{Fetch: fetch, CVEBase: "http://nvdcve"},
		KEV:  &kev.Provider{Fetch: fetch, FeedURL: "http://kevfeed"},
		EPSS: &epss.Provider{Fetch: fetch, APIBase: "http://epssapi"},
	}
	target, _ := cpe.Parse("cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*")
	vulns, err := intel.CVEsFor(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 1 {
		t.Fatalf("want 1 vuln, got %d", len(vulns))
	}
	v := vulns[0]
	if v.ID != "CVE-2024-0001" || !v.KEV || v.EPSS != 0.87 || v.CVSS != 8.1 || v.FixedVersion != "3.0.12" {
		t.Fatalf("enrichment wrong: %+v", v)
	}
	if v.KEVDateAdded != "2026-07-02" {
		t.Errorf("kev date = %q", v.KEVDateAdded)
	}
	if p, _ := Rank(v); p != P1 {
		t.Errorf("KEV vuln should rank P1, got %s", p)
	}
}
