// Package epss reads FIRST EPSS scores — the probability a CVE will be exploited
// in the next 30 days. Scores are cached per CVE with a TTL so a CVE that
// affects several inventory items is fetched once, not once per item.
package epss

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultAPIBase is FIRST's public EPSS API.
const DefaultAPIBase = "https://api.first.org/data/v1/epss"

// Fetcher retrieves the bytes at a URL. Injected so tests run offline.
type Fetcher func(ctx context.Context, url string) ([]byte, error)

// Provider fetches and caches EPSS scores.
type Provider struct {
	Fetch   Fetcher
	APIBase string
	TTL     time.Duration
	Now     func() time.Time

	mu     sync.Mutex
	cache  map[string]entry
}

type entry struct {
	score   float64
	fetched time.Time
}

// Scores returns EPSS probabilities for the given CVEs. Cached CVEs are served
// from memory; the rest are fetched in one batched request. A CVE with no EPSS
// score maps to 0. A fetch error returns whatever was cached plus the error.
func (p *Provider) Scores(ctx context.Context, cves []string) (map[string]float64, error) {
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	ttl := p.TTL
	if ttl <= 0 {
		ttl = 6 * time.Hour
	}

	out := make(map[string]float64, len(cves))
	var missing []string

	p.mu.Lock()
	if p.cache == nil {
		p.cache = map[string]entry{}
	}
	for _, c := range cves {
		if e, ok := p.cache[c]; ok && now().Sub(e.fetched) < ttl {
			out[c] = e.score
		} else if c != "" {
			missing = append(missing, c)
		}
	}
	p.mu.Unlock()

	if len(missing) == 0 {
		return out, nil
	}

	base := p.APIBase
	if base == "" {
		base = DefaultAPIBase
	}
	u := base + "?cve=" + url.QueryEscape(strings.Join(missing, ","))
	body, err := p.Fetch(ctx, u)
	if err != nil {
		return out, err
	}
	fetched, perr := parse(body)
	if perr != nil {
		return out, perr
	}

	p.mu.Lock()
	for _, c := range missing {
		score := fetched[c] // 0 if absent
		p.cache[c] = entry{score: score, fetched: now()}
		out[c] = score
	}
	p.mu.Unlock()
	return out, nil
}

type apiResp struct {
	Data []struct {
		CVE  string `json:"cve"`
		EPSS string `json:"epss"`
	} `json:"data"`
}

func parse(body []byte) (map[string]float64, error) {
	var r apiResp
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	m := make(map[string]float64, len(r.Data))
	for _, d := range r.Data {
		f, err := strconv.ParseFloat(d.EPSS, 64)
		if err != nil {
			continue
		}
		m[d.CVE] = f
	}
	return m, nil
}
