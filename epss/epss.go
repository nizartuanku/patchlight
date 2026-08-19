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

	mu    sync.Mutex
	cache map[string]entry
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

	// Request in pages. The API caps how many records it returns per call and
	// simply returns fewer than asked rather than erroring, so one request
	// carrying a whole inventory silently loses everything past the first page —
	// and those CVEs would then be cached as 0.0 for the TTL, sinking genuinely
	// exploited vulnerabilities to the bottom of an exploitation-first list.
	// Paging also keeps the query string a sane length.
	for start := 0; start < len(missing); start += pageSize {
		end := start + pageSize
		if end > len(missing) {
			end = len(missing)
		}
		page := missing[start:end]

		u := base + "?limit=" + strconv.Itoa(pageSize) +
			"&cve=" + url.QueryEscape(strings.Join(page, ","))
		body, err := p.Fetch(ctx, u)
		if err != nil {
			return out, err // partial results plus the error; the caller decides
		}
		fetched, perr := parse(body)
		if perr != nil {
			return out, perr
		}

		// Only cache the page we actually got an answer for. A CVE genuinely
		// absent from the response has no published score, which is a real 0.
		p.mu.Lock()
		for _, c := range page {
			score := fetched[c]
			p.cache[c] = entry{score: score, fetched: now()}
			out[c] = score
		}
		p.mu.Unlock()
	}
	return out, nil
}

// pageSize is how many CVEs are requested per call: FIRST's API returns at most
// its own page limit per request no matter how many ids are supplied.
const pageSize = 100

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
