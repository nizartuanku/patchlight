package cpe

import "testing"

func TestParseRoundTrip(t *testing.T) {
	in := "cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*"
	c, err := Parse(in)
	if err != nil {
		t.Fatal(err)
	}
	if c.Part != "a" || c.Vendor != "openssl" || c.Product != "openssl" || c.Version != "3.0.11" {
		t.Fatalf("parsed wrong: %+v", c)
	}
	if got := c.String(); got != in {
		t.Errorf("round-trip: got %q want %q", got, in)
	}
	if c.Label() != "openssl 3.0.11" {
		t.Errorf("label = %q", c.Label())
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"nginx 1.24", "cpe:2.3:x:v:p:1", "cpe:2.3:a:vendor::1.0"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestFromProductVersion(t *testing.T) {
	c, err := FromProductVersion("NGINX", "1.24.0")
	if err != nil {
		t.Fatal(err)
	}
	if c.Product != "nginx" || c.Version != "1.24.0" || c.Vendor != "*" {
		t.Fatalf("got %+v", c)
	}
	if c.String() != "cpe:2.3:a:*:nginx:1.24.0:*:*:*:*:*:*:*" {
		t.Errorf("string = %q", c.String())
	}
}

func TestParseSBOM_CycloneDX(t *testing.T) {
	doc := `{"bomFormat":"CycloneDX","components":[
	  {"name":"openssl","version":"3.0.11","cpe":"cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*"},
	  {"name":"nginx","version":"1.24.0","purl":"pkg:generic/nginx@1.24.0"},
	  {"name":"leftpad","version":"1.0.0"}
	]}`
	comps, err := ParseSBOM([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 3 {
		t.Fatalf("want 3 components, got %d", len(comps))
	}
	if comps[0].Source != "cpe" || comps[0].CPE.Vendor != "openssl" {
		t.Errorf("comp0 = %+v", comps[0])
	}
	if comps[1].Source != "purl" || comps[1].CPE.Product != "nginx" {
		t.Errorf("comp1 = %+v", comps[1])
	}
	if comps[2].Source != "derived" || comps[2].CPE.Product != "leftpad" {
		t.Errorf("comp2 = %+v", comps[2])
	}
}

func TestParseSBOM_SPDX(t *testing.T) {
	doc := `{"spdxVersion":"SPDX-2.3","packages":[
	  {"name":"openssl","versionInfo":"3.0.11","externalRefs":[
	    {"referenceType":"cpe23Type","referenceLocator":"cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*"}]}
	]}`
	comps, err := ParseSBOM([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 1 || comps[0].CPE.Product != "openssl" || comps[0].Source != "cpe" {
		t.Fatalf("got %+v", comps)
	}
}

func TestParsePURL(t *testing.T) {
	n, v, ok := parsePURL("pkg:golang/github.com/foo/bar@1.2.3?type=module")
	if !ok || n != "bar" || v != "1.2.3" {
		t.Fatalf("got %q %q %v", n, v, ok)
	}
}
