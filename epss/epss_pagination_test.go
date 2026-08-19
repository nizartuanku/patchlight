package epss

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// fakeFIRST emulates the documented behaviour of FIRST's EPSS API: the response
// is paginated, `limit` defaults to 100, and the envelope reports total/offset/
// limit so a client can page. Anything past the first page is simply not in
// `data` — the API does not error, it just returns less than you asked for.
func fakeFIRST(scores map[string]float64) Fetcher {
	return func(_ context.Context, raw string) ([]byte, error) {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		asked := strings.Split(q.Get("cve"), ",")
		limit := 100
		if l := q.Get("limit"); l != "" {
			limit, _ = strconv.Atoi(l)
		}
		offset := 0
		if o := q.Get("offset"); o != "" {
			offset, _ = strconv.Atoi(o)
		}
		type row struct {
			CVE  string `json:"cve"`
			EPSS string `json:"epss"`
		}
		var data []row
		for i := offset; i < len(asked) && len(data) < limit; i++ {
			if s, ok := scores[asked[i]]; ok {
				data = append(data, row{CVE: asked[i], EPSS: fmt.Sprintf("%.5f", s)})
			}
		}
		return json.Marshal(map[string]any{
			"status": "OK", "total": len(asked), "offset": offset,
			"limit": limit, "data": data,
		})
	}
}

// A real inventory easily exceeds 100 CVEs. Everything past the first page must
// still get its true score — not a silent 0 that is then cached for the TTL.
func TestScoresBeyondOnePage(t *testing.T) {
	const n = 250
	want := map[string]float64{}
	var cves []string
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("CVE-2024-%05d", i)
		cves = append(cves, id)
		want[id] = 0.5 // every one of them is genuinely high-probability
	}

	p := &Provider{Fetch: fakeFIRST(want)}
	got, err := p.Scores(context.Background(), cves)
	if err != nil {
		t.Fatalf("Scores: %v", err)
	}

	var zeroed []string
	for _, c := range cves {
		if got[c] == 0 {
			zeroed = append(zeroed, c)
		}
	}
	if len(zeroed) > 0 {
		t.Fatalf("%d of %d CVEs came back as EPSS 0 despite having a real score "+
			"(first: %s). They rank last in an exploitation-first list, and the 0 "+
			"is cached for the TTL.", len(zeroed), n, zeroed[0])
	}
}
