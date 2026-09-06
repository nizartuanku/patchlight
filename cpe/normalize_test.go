package cpe

import "testing"

// Ground truth: the CPE name NVD indexes each of these under, and the CVE count
// each form returned from the live API on 5 Sep 2026. The naive column is what
// this package produced before — three of these were exactly zero, which is the
// whole of the "19 of 25 targets return no findings" report.
func TestNormalize_MatchesTheNameNVDIndexes(t *testing.T) {
	cases := []struct {
		display   string
		version   string
		wantCPE   string
		wasBroken bool // returned zero CVEs before this change
	}{
		{"nginx", "1.24.0", "cpe:2.3:a:*:nginx:1.24.0:*:*:*:*:*:*:*", false},
		{"OpenSSH", "9.6", "cpe:2.3:a:*:openssh:9.6:*:*:*:*:*:*:*", false},
		{"OpenSSL", "3.0.11", "cpe:2.3:a:*:openssl:3.0.11:*:*:*:*:*:*:*", false},
		{"MySQL", "8.0.35", "cpe:2.3:a:*:mysql:8.0.35:*:*:*:*:*:*:*", false},
		{"PostgreSQL", "15.5", "cpe:2.3:a:*:postgresql:15.5:*:*:*:*:*:*:*", false},
		{"Redis", "7.2.3", "cpe:2.3:a:*:redis:7.2.3:*:*:*:*:*:*:*", false},

		// Vendor word glued into the product token — found nothing before.
		{"Apache HTTP Server", "2.4.57", "cpe:2.3:a:*:http_server:2.4.57:*:*:*:*:*:*:*", true},
		{"Apache Tomcat", "9.0.83", "cpe:2.3:a:*:tomcat:9.0.83:*:*:*:*:*:*:*", true},

		// Operating systems: part "o". Every one of these returned zero.
		{"Linux Kernel", "6.8", "cpe:2.3:o:*:linux_kernel:6.8:*:*:*:*:*:*:*", true},
		{"Ubuntu Linux", "22.04", "cpe:2.3:o:*:ubuntu_linux:22.04:*:*:*:*:*:*:*", true},
		{"Windows Server 2019", "", "cpe:2.3:o:*:windows_server_2019:*:*:*:*:*:*:*:*", true},
		{"Debian", "12", "cpe:2.3:o:*:debian_linux:12.0:*:*:*:*:*:*:*", true},
		{"FreeBSD", "14.0", "cpe:2.3:o:*:freebsd:14.0:*:*:*:*:*:*:*", true},
	}
	broken := 0
	for _, c := range cases {
		got, err := FromProductVersion(c.display, c.version)
		if err != nil {
			t.Fatalf("%s: %v", c.display, err)
		}
		if got.String() != c.wantCPE {
			t.Errorf("%s %s\n  got  %s\n  want %s", c.display, c.version, got.String(), c.wantCPE)
		}
		if c.wasBroken {
			broken++
		}
	}
	if broken == 0 {
		t.Fatal("this table has stopped covering the cases that were broken")
	}
}

// The part field is what made operating systems invisible: NVD indexes them
// under "o", and a query that says "a" returns nothing at all.
func TestNormalize_OperatingSystemsGetPartO(t *testing.T) {
	for _, name := range []string{
		"Linux Kernel", "linux", "Ubuntu", "Debian", "CentOS", "Alpine Linux",
		"FreeBSD", "macOS", "Android", "Windows 11", "Windows Server 2022",
		"ESXi 8.0", "FortiOS", "PAN-OS",
	} {
		part, prod := Normalize(name)
		if part != "o" {
			t.Errorf("Normalize(%q) = part %q, product %q — want part o", name, part, prod)
		}
	}
}

// And ordinary applications must not be dragged along with them.
func TestNormalize_ApplicationsStayPartA(t *testing.T) {
	for _, name := range []string{
		"nginx", "OpenSSL", "MySQL", "PostgreSQL", "Redis", "Node.js",
		"Apache Tomcat", "Elasticsearch", "curl",
	} {
		if part, prod := Normalize(name); part != "a" {
			t.Errorf("Normalize(%q) = part %q, product %q — want part a", name, part, prod)
		}
	}
}

// A distribution release is indexed with an explicit minor. Debian 12 returns
// nothing; debian_linux 12.0 returns 294. The missing ".0" is a third way for a
// target to look clean while being unreadable, alongside the wrong part and the
// wrong product token.
func TestNormalizeVersion_DistributionReleasesGetTheirMinor(t *testing.T) {
	for _, c := range []struct{ part, in, want string }{
		{"o", "12", "12.0"}, // Debian 12   ->   0 CVEs, 12.0 -> 294
		{"o", "9", "9.0"},   // RHEL 9      ->   3 CVEs,  9.0 -> 595
		{"o", "7", "7.0"},   // CentOS 7    ->   0 CVEs,  7.0 ->   2
		{"o", "22.04", "22.04"},
		{"o", "6.8", "6.8"},
		{"a", "9", "9"}, // tomcat 9 and 9.0 both return 14 — leave it alone
		{"a", "8", "8"},
		{"o", "", "*"},
	} {
		if got := NormalizeVersion(c.part, c.in); got != c.want {
			t.Errorf("NormalizeVersion(%q, %q) = %q, want %q", c.part, c.in, got, c.want)
		}
	}
}

// The vendor stays a wildcard on purpose. Measured against NVD, the wildcard
// matched the vendor-specific count everywhere and beat it twice; a guessed
// vendor can only narrow, and narrowing on a guess is how a scanner reports
// "no findings" for a product that has thousands.
func TestNormalize_VendorStaysWildcard(t *testing.T) {
	for _, name := range []string{"Apache HTTP Server", "Linux Kernel", "nginx"} {
		c, err := FromProductVersion(name, "1.0")
		if err != nil {
			t.Fatal(err)
		}
		if c.Vendor != "*" {
			t.Errorf("FromProductVersion(%q) pinned vendor %q", name, c.Vendor)
		}
	}
}
