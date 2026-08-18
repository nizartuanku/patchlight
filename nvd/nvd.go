// Package nvd queries the NIST National Vulnerability Database: the CVEs that
// affect a given CPE (letting NVD do the version-range matching), and a
// best-effort resolver from a free-text product+version to a CPE. HTTP is
// injected so tests run offline; responses are cached per query with a TTL to
// respect NVD's rate limits.
package nvd

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nizartuanku/patchlight/cpe"
)

const (
	DefaultCVEBase = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	DefaultCPEBase = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
)

// Fetcher retrieves the bytes at a URL. Injected so tests run offline.
type Fetcher func(ctx context.Context, url string) ([]byte, error)

// CVE is the subset of an NVD record Patchlight needs.
type CVE struct {
	ID           string
	Summary      string
	CVSS         float64
	CVSSVector   string
	FixedVersion string // versionEndExcluding, when NVD gives one
	VersionRange string // human hint, e.g. ">= 1.20.0, < 1.24.1"
	MatchedCPE   string
	URL          string
}

// Client queries NVD.
type Client struct {
	Fetch   Fetcher
	CVEBase string
	CPEBase string
	APIKey  string // optional; raises the rate limit
	TTL     time.Duration
	Now     func() time.Time

	mu    sync.Mutex
	cache map[string]cveCacheEntry
}

type cveCacheEntry struct {
	cves    []CVE
	fetched time.Time
}

// CVEsFor returns the CVEs affecting a CPE. NVD performs the version-range
// matching via virtualMatchString, so this package never reimplements CPE
// applicability logic.
func (c *Client) CVEsFor(ctx context.Context, target cpe.CPE) ([]CVE, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	ttl := c.TTL
	if ttl <= 0 {
		ttl = 6 * time.Hour
	}
	key := target.Canonical()

	c.mu.Lock()
	if c.cache == nil {
		c.cache = map[string]cveCacheEntry{}
	}
	if e, ok := c.cache[key]; ok && now().Sub(e.fetched) < ttl {
		c.mu.Unlock()
		return e.cves, nil
	}
	c.mu.Unlock()

	base := c.CVEBase
	if base == "" {
		base = DefaultCVEBase
	}
	u := base + "?virtualMatchString=" + url.QueryEscape(target.Canonical())
	body, err := c.Fetch(ctx, u)
	if err != nil {
		return nil, err
	}
	cves, err := parseCVEs(body)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.cache[key] = cveCacheEntry{cves: cves, fetched: now()}
	c.mu.Unlock()
	return cves, nil
}

// Resolve turns a free-text product (and version) into a CPE, best-effort, via
// the NVD CPE dictionary. If nothing matches, it falls back to a wildcard-vendor
// CPE so matching still works through NVD's own logic.
func (c *Client) Resolve(ctx context.Context, product, version string) (cpe.CPE, error) {
	base := c.CPEBase
	if base == "" {
		base = DefaultCPEBase
	}
	u := base + "?keywordSearch=" + url.QueryEscape(product)
	body, err := c.Fetch(ctx, u)
	if err != nil {
		return cpe.FromProductVersion(product, version)
	}
	name, ok := parseTopCPE(body)
	if !ok {
		return cpe.FromProductVersion(product, version)
	}
	base23, err := cpe.Parse(name)
	if err != nil {
		return cpe.FromProductVersion(product, version)
	}
	base23.Version = normalizeVersion(version)
	// Clear fields below version so the name stays a clean product+version key.
	base23.Update, base23.Edition, base23.Language = "*", "*", "*"
	base23.SWEdition, base23.TargetSW, base23.TargetHW, base23.Other = "*", "*", "*", "*"
	return base23, nil
}

func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "*"
	}
	return v
}

// --- NVD JSON shapes --------------------------------------------------------

type cveFeed struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				V31 []metric `json:"cvssMetricV31"`
				V30 []metric `json:"cvssMetricV30"`
				V2  []metric `json:"cvssMetricV2"`
			} `json:"metrics"`
			Configurations []struct {
				Nodes []struct {
					CpeMatch []struct {
						Vulnerable            bool   `json:"vulnerable"`
						Criteria              string `json:"criteria"`
						VersionStartIncluding string `json:"versionStartIncluding"`
						VersionEndExcluding   string `json:"versionEndExcluding"`
						VersionEndIncluding   string `json:"versionEndIncluding"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type metric struct {
	CvssData struct {
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
}

func parseCVEs(body []byte) ([]CVE, error) {
	var f cveFeed
	if err := json.Unmarshal(body, &f); err != nil {
		return nil, err
	}
	out := make([]CVE, 0, len(f.Vulnerabilities))
	for _, item := range f.Vulnerabilities {
		v := item.CVE
		c := CVE{ID: v.ID, URL: "https://nvd.nist.gov/vuln/detail/" + v.ID}
		for _, d := range v.Descriptions {
			if d.Lang == "en" {
				c.Summary = d.Value
				break
			}
		}
		c.CVSS, c.CVSSVector = bestCVSS(v.Metrics.V31, v.Metrics.V30, v.Metrics.V2)
		c.FixedVersion, c.VersionRange, c.MatchedCPE = versionInfo(v.Configurations)
		out = append(out, c)
	}
	return out, nil
}

func bestCVSS(groups ...[]metric) (float64, string) {
	for _, g := range groups {
		if len(g) > 0 {
			return g[0].CvssData.BaseScore, g[0].CvssData.VectorString
		}
	}
	return 0, ""
}

func versionInfo(configs []struct {
	Nodes []struct {
		CpeMatch []struct {
			Vulnerable            bool   `json:"vulnerable"`
			Criteria              string `json:"criteria"`
			VersionStartIncluding string `json:"versionStartIncluding"`
			VersionEndExcluding   string `json:"versionEndExcluding"`
			VersionEndIncluding   string `json:"versionEndIncluding"`
		} `json:"cpeMatch"`
	} `json:"nodes"`
}) (fixed, rng, matched string) {
	for _, cfg := range configs {
		for _, node := range cfg.Nodes {
			for _, m := range node.CpeMatch {
				if !m.Vulnerable {
					continue
				}
				matched = m.Criteria
				var parts []string
				if m.VersionStartIncluding != "" {
					parts = append(parts, "≥ "+m.VersionStartIncluding)
				}
				if m.VersionEndExcluding != "" {
					parts = append(parts, "< "+m.VersionEndExcluding)
					fixed = m.VersionEndExcluding
				} else if m.VersionEndIncluding != "" {
					parts = append(parts, "≤ "+m.VersionEndIncluding)
				}
				if len(parts) > 0 {
					rng = strings.Join(parts, ", ")
				}
				return fixed, rng, matched
			}
		}
	}
	return "", "", ""
}

func parseTopCPE(body []byte) (string, bool) {
	var r struct {
		Products []struct {
			CPE struct {
				CpeName    string `json:"cpeName"`
				Deprecated bool   `json:"deprecated"`
			} `json:"cpe"`
		} `json:"products"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return "", false
	}
	for _, p := range r.Products {
		if !p.CPE.Deprecated && strings.HasPrefix(p.CPE.CpeName, "cpe:2.3:a:") {
			return p.CPE.CpeName, true
		}
	}
	for _, p := range r.Products {
		if p.CPE.CpeName != "" {
			return p.CPE.CpeName, true
		}
	}
	return "", false
}
