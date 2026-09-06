package nvd

import (
	"strings"
	"testing"

	"github.com/nizartuanku/patchlight/cpe"
)

// A CVE that needs two products present at once lists both in one
// configuration. CVE-2019-0190 is the real case: Apache httpd AND OpenSSL. The
// old code took the first vulnerable cpeMatch in the node, so an OpenSSL owner
// was told their fix version was an httpd release number. The CVE was right;
// the evidence was another product's, which is worse, because the evidence is
// what someone acts on.
const twoProductFeed = `{"vulnerabilities":[{"cve":{
 "id":"CVE-2019-0190",
 "descriptions":[{"lang":"en","value":"Apache httpd with OpenSSL 1.1.1 can be forced into an infinite loop."}],
 "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.5,"vectorString":"CVSS:3.1/AV:N"}}]},
 "configurations":[{"nodes":[
   {"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*","versionStartIncluding":"2.4.37","versionEndIncluding":"2.4.37"}]},
   {"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*","versionEndExcluding":"1.1.1a"}]}
 ]}],
 "references":[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2019-0190"}]
}}]}`

func TestVersionInfo_EvidenceComesFromTheTargetsOwnMatch(t *testing.T) {
	target, err := cpe.Parse("cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatal(err)
	}
	cves, err := parseCVEs([]byte(twoProductFeed), target)
	if err != nil {
		t.Fatal(err)
	}
	if len(cves) != 1 {
		t.Fatalf("got %d CVEs", len(cves))
	}
	c := cves[0]
	if !strings.Contains(c.MatchedCPE, "openssl") {
		t.Fatalf("matched CPE is %q — the evidence belongs to another product", c.MatchedCPE)
	}
	if c.FixedVersion != "1.1.1a" {
		t.Errorf("FixedVersion = %q, want 1.1.1a (an OpenSSL release, not an httpd one)", c.FixedVersion)
	}
	if strings.Contains(c.FixedVersion, "2.4.") {
		t.Errorf("FixedVersion %q is an Apache httpd version reported against an OpenSSL target", c.FixedVersion)
	}
}

// The same feed seen from the other side has to give the other product's
// evidence — the rule is "the target's own match", not "the second one".
func TestVersionInfo_TheOtherTargetGetsItsOwnEvidence(t *testing.T) {
	target, _ := cpe.Parse("cpe:2.3:a:apache:http_server:2.4.37:*:*:*:*:*:*:*")
	cves, err := parseCVEs([]byte(twoProductFeed), target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cves[0].MatchedCPE, "http_server") {
		t.Fatalf("matched CPE is %q, want the httpd match", cves[0].MatchedCPE)
	}
}

// When the configuration never names the target, no version evidence is
// reported. An empty field is honest; a borrowed one is not.
func TestVersionInfo_NoBorrowedEvidence(t *testing.T) {
	target, _ := cpe.Parse("cpe:2.3:a:*:nginx:1.24.0:*:*:*:*:*:*:*")
	cves, err := parseCVEs([]byte(twoProductFeed), target)
	if err != nil {
		t.Fatal(err)
	}
	c := cves[0]
	if c.MatchedCPE != "" || c.FixedVersion != "" || c.VersionRange != "" {
		t.Fatalf("reported another product's evidence: matched=%q fixed=%q range=%q", c.MatchedCPE, c.FixedVersion, c.VersionRange)
	}
	if c.ID != "CVE-2019-0190" || c.CVSS != 7.5 {
		t.Errorf("the CVE itself must still be reported: %+v", c)
	}
}

// A wildcarded field on either side cannot disagree, so a target derived from a
// package name (vendor "*") still collects its evidence.
func TestVersionInfo_WildcardVendorTargetStillMatches(t *testing.T) {
	target, _ := cpe.Parse("cpe:2.3:a:*:openssl:1.1.1:*:*:*:*:*:*:*")
	cves, _ := parseCVEs([]byte(twoProductFeed), target)
	if cves[0].FixedVersion != "1.1.1a" {
		t.Fatalf("FixedVersion = %q, want 1.1.1a", cves[0].FixedVersion)
	}
}

const dictFeed = `{"products":[
 {"cpe":{"cpeName":"cpe:2.3:a:apache:http_server_project:1.0:*:*:*:*:*:*:*","deprecated":false}},
 {"cpe":{"cpeName":"cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*","deprecated":false}},
 {"cpe":{"cpeName":"cpe:2.3:a:someone:apache_http_server_plugin:1.0:*:*:*:*:*:*:*","deprecated":false}}
]}`

// The dictionary search returns whatever matched the keywords, in its own
// order. Taking the first entry is how a search for one product resolves to a
// plugin for it.
func TestParseTopCPE_PrefersTheExactProduct(t *testing.T) {
	got, ok := parseTopCPE([]byte(dictFeed), "http_server")
	if !ok {
		t.Fatal("no candidate chosen")
	}
	if got != "cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*" {
		t.Fatalf("chose %q", got)
	}
}

const osDictFeed = `{"products":[
 {"cpe":{"cpeName":"cpe:2.3:o:linux:linux_kernel:6.8:*:*:*:*:*:*:*","deprecated":false}}
]}`

// The old code required a "cpe:2.3:a:" prefix, so an operating system could
// never be resolved from the dictionary at all.
func TestParseTopCPE_AcceptsOperatingSystems(t *testing.T) {
	got, ok := parseTopCPE([]byte(osDictFeed), "linux_kernel")
	if !ok || !strings.HasPrefix(got, "cpe:2.3:o:") {
		t.Fatalf("got %q ok=%v — an OS entry must be usable", got, ok)
	}
}

const deprecatedFeed = `{"products":[
 {"cpe":{"cpeName":"cpe:2.3:a:vendor:widget:1.0:*:*:*:*:*:*:*","deprecated":true}},
 {"cpe":{"cpeName":"cpe:2.3:a:vendor:widget:2.0:*:*:*:*:*:*:*","deprecated":false}}
]}`

func TestParseTopCPE_SkipsDeprecated(t *testing.T) {
	got, _ := parseTopCPE([]byte(deprecatedFeed), "widget")
	if got != "cpe:2.3:a:vendor:widget:2.0:*:*:*:*:*:*:*" {
		t.Fatalf("chose the deprecated entry: %q", got)
	}
}
