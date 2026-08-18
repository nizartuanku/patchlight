// Package kev reads the CISA Known Exploited Vulnerabilities catalogue — the
// single strongest "patch this now" signal. It caches the feed so every target
// in a scan cycle reads one shared copy rather than re-fetching.
package kev

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// DefaultFeedURL is CISA's public KEV JSON feed.
const DefaultFeedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// Fetcher retrieves the bytes at a URL. Injected so tests run offline.
type Fetcher func(ctx context.Context, url string) ([]byte, error)

// Catalog is an immutable snapshot: CVE id → date added to KEV.
type Catalog struct {
	added map[string]string
}

// Has reports whether a CVE is on the KEV list.
func (c Catalog) Has(cve string) bool { _, ok := c.added[cve]; return ok }

// DateAdded returns the KEV date-added for a CVE (empty if not listed).
func (c Catalog) DateAdded(cve string) string { return c.added[cve] }

// Len is the number of catalogued CVEs.
func (c Catalog) Len() int { return len(c.added) }

// Provider fetches and caches the KEV catalogue with a TTL.
type Provider struct {
	Fetch   Fetcher
	FeedURL string
	TTL     time.Duration
	Now     func() time.Time

	mu       sync.Mutex
	cache    Catalog
	fetched  time.Time
	hasCache bool
}

// Get returns the catalogue, refreshing it if the TTL has elapsed. On a refresh
// error it returns the last good snapshot if there is one (stale is better than
// blind), else the error.
func (p *Provider) Get(ctx context.Context) (Catalog, error) {
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	ttl := p.TTL
	if ttl <= 0 {
		ttl = 6 * time.Hour
	}
	url := p.FeedURL
	if url == "" {
		url = DefaultFeedURL
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.hasCache && now().Sub(p.fetched) < ttl {
		return p.cache, nil
	}
	body, err := p.Fetch(ctx, url)
	if err != nil {
		if p.hasCache {
			return p.cache, nil
		}
		return Catalog{}, err
	}
	cat, err := parse(body)
	if err != nil {
		if p.hasCache {
			return p.cache, nil
		}
		return Catalog{}, err
	}
	p.cache = cat
	p.fetched = now()
	p.hasCache = true
	return cat, nil
}

type feed struct {
	Vulnerabilities []struct {
		CveID     string `json:"cveID"`
		DateAdded string `json:"dateAdded"`
	} `json:"vulnerabilities"`
}

func parse(body []byte) (Catalog, error) {
	var f feed
	if err := json.Unmarshal(body, &f); err != nil {
		return Catalog{}, err
	}
	m := make(map[string]string, len(f.Vulnerabilities))
	for _, v := range f.Vulnerabilities {
		if v.CveID != "" {
			m[v.CveID] = v.DateAdded
		}
	}
	return Catalog{added: m}, nil
}
