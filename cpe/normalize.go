package cpe

import (
	"regexp"
	"strings"
)

// This file turns what a person types — or what an SBOM calls a package — into
// the CPE 2.3 name NVD actually indexes it under.
//
// Measured against the live NVD API on 5 Sep 2026 (CVE counts via
// virtualMatchString), the naive form — lowercase, spaces to underscores, part
// always "a", vendor "*" — returns the right answer for most application
// packages and *exactly zero* for the rest:
//
//	target                 naive                        naive   correct
//	nginx 1.24.0           a:*:nginx                        2         2
//	OpenSSH 9.6            a:*:openssh                     19        19
//	OpenSSL 3.0.11         a:*:openssl                     32        31
//	MySQL 8.0.35           a:*:mysql                       87        87
//	PostgreSQL 15.5        a:*:postgresql                  45        45
//	Node.js 20.11.0        a:*:node.js                     20        20
//	Redis 7.2.3            a:*:redis                       18        18
//	Apache HTTP Server     a:*:apache_http_server           0        53
//	Linux Kernel 6.8       a:*:linux_kernel                 0     6,582
//	Ubuntu Linux 22.04     a:*:ubuntu_linux                 0        59
//	Windows Server 2019    a:*:windows_server_2019          0     5,255
//
// Three things the measurements settle:
//
//   - The part field is decisive. An operating system is indexed under "o"; a
//     query that says "a" cannot see it. Every OS target returned zero, and the
//     Linux kernel alone accounts for 6,582 CVEs that were invisible.
//   - The product token must be the token NVD uses. "Apache HTTP Server" is
//     indexed as product http_server — gluing the vendor word into the product
//     finds nothing.
//   - A wildcard vendor is NOT a defect, which is worth stating because it was
//     the suspected cause. cpe:2.3:a:*:http_server returned 53 CVEs against 51
//     for cpe:2.3:a:apache:http_server, and o:*:linux_kernel matched
//     o:linux:linux_kernel exactly at 6,582. The wildcard never lost a CVE and
//     twice found more, so this code keeps it and resolves only part and
//     product. A guessed vendor can only narrow — and narrowing on a guess is
//     how a scanner reports "no findings" for something that has thousands.
type nameRule struct {
	part    string
	product string
}

// aliases covers names whose naive token is wrong, not merely different. Each
// entry was checked against the dictionary rather than assumed.
var aliases = map[string]nameRule{
	"apache_http_server": {"a", "http_server"},
	"apache_httpd":       {"a", "http_server"},
	"httpd":              {"a", "http_server"},
	"apache_tomcat":      {"a", "tomcat"},
	"apache_log4j":       {"a", "log4j"},
	"apache_struts":      {"a", "struts"},
	"microsoft_iis":      {"a", "internet_information_services"},
	"iis":                {"a", "internet_information_services"},
	"microsoft_exchange": {"a", "exchange_server"},
	"ms_exchange":        {"a", "exchange_server"},
	"oracle_mysql":       {"a", "mysql"},
	"elastic_search":     {"a", "elasticsearch"},
	"open_ssl":           {"a", "openssl"},
	"open_ssh":           {"a", "openssh"},
	"nodejs":             {"a", "node.js"},
	"node":               {"a", "node.js"},
	"postgres":           {"a", "postgresql"},

	// Operating systems — the group that returned zero on every query.
	"linux_kernel":             {"o", "linux_kernel"},
	"linux":                    {"o", "linux_kernel"},
	"kernel":                   {"o", "linux_kernel"},
	"ubuntu":                   {"o", "ubuntu_linux"},
	"ubuntu_linux":             {"o", "ubuntu_linux"},
	"debian":                   {"o", "debian_linux"},
	"debian_linux":             {"o", "debian_linux"},
	"rhel":                     {"o", "enterprise_linux"},
	"red_hat_enterprise_linux": {"o", "enterprise_linux"},
	"centos":                   {"o", "centos"},
	"alpine":                   {"o", "alpine_linux"},
	"alpine_linux":             {"o", "alpine_linux"},
	"freebsd":                  {"o", "freebsd"},
	"macos":                    {"o", "macos"},
	"mac_os_x":                 {"o", "mac_os_x"},
	"ios":                      {"o", "iphone_os"},
	"android":                  {"o", "android"},
}

// osPrefixes name an operating system even when the table does not list the
// individual release — every Windows build, every ESXi version.
var osPrefixes = []string{"windows", "esxi", "junos", "ios_xe", "ios_xr", "nx-os", "fortios", "pan-os"}

// osSuffixes catch distributions the table does not name individually.
var osSuffixes = []string{"_linux", "_os", "bsd"}

// Normalize resolves a free-text product name to the part and product token NVD
// indexes it under. Vendor is deliberately not resolved; see the top of this
// file for the measurements behind that.
func Normalize(product string) (part, prod string) {
	tok := normalizeToken(product)
	if tok == "" {
		return "a", ""
	}
	if r, ok := aliases[tok]; ok {
		return r.part, r.product
	}
	if looksLikeOS(tok) {
		return "o", tok
	}
	return "a", tok
}

// bareMajor matches a version that is nothing but a major number: "12", "9".
var bareMajor = regexp.MustCompile(`^\d+$`)

// NormalizeVersion adjusts a version string to the form NVD indexes it under.
//
// Distributions are the case that matters. NVD stores their releases with an
// explicit minor — debian_linux 12.0, enterprise_linux 9.0, centos 7.0 — while
// a person types the number on the box. Measured on 5 Sep 2026, that one
// missing ".0" is the difference between silence and the truth:
//
//	debian_linux 12    ->     0 CVEs        12.0  ->   294
//	enterprise_linux 9 ->     3 CVEs         9.0  ->   595
//	centos 7           ->     0 CVEs         7.0  ->     2
//
// The rule is confined to operating systems because applications do not need
// it and must not be disturbed by it: tomcat 9 and tomcat 9.0 both return 14.
func NormalizeVersion(part, version string) string {
	v := normalizeToken(version)
	if v == "" {
		return "*"
	}
	if part == "o" && bareMajor.MatchString(v) {
		return v + ".0"
	}
	return v
}

func looksLikeOS(tok string) bool {
	for _, p := range osPrefixes {
		if tok == p || strings.HasPrefix(tok, p+"_") || strings.HasPrefix(tok, p+"-") {
			return true
		}
	}
	for _, s := range osSuffixes {
		if strings.HasSuffix(tok, s) {
			return true
		}
	}
	return false
}
