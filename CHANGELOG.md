# Changelog

## 0.1.2 — 2026-09-07

### The free edition now holds 150 inventory items

The free tier carried a 25-item cap inherited from an earlier product, well
below the size of the estate most people want to point it at first. Free now
holds **150 items**. Pro stays at 500, Team stays unlimited.

The edition table in the README had drifted from the code in three other rows,
and the code was right every time: the free scan interval is every 12 hours and
fixed, free alert channels are webhook **and** syslog, and the offline /
air-gapped mirror flags were never gated by tier at all. The table now says what
the binary does. The tests that pinned the free limit read the tier table instead
of a hardcoded number, so the next change to a cap cannot quietly break them.

### Verification identifiers renamed to Hexward

The HTTP header, DNS TXT label and well-known file used to prove domain
ownership still carried the pre-rename brand. They are now `X-Hexward-Token`,
`_hexward-verify.<domain>` and `/.well-known/hexward-verify.txt`.

Nothing already installed breaks. Verification accepts either the old or the new
name, and the webhook sends both headers, so a receiver written against the old
one keeps working with no change at either end. The old names are removed on
**1 March 2027**. New installations, the wizard and the documentation show only
the new names.

### Where the paid editions are, from inside the product

The licence panel, the footer, and the message you get when a free-edition limit
is reached now all point at the product page. No banner, no modal, no countdown —
the free edition is meant to be useful on its own.

### docs/CONCEPTS.md

A new document on what Patchlight is reasoning about: CPE, KEV, EPSS, and why a
target that returns no findings is the first thing to check rather than the last.

## 0.1.1 — 2026-09-06

### Targets that returned no findings at all

Free-text product names were turned into CPEs by lowercasing them, replacing
spaces with underscores, and always saying part `a`. Measured against the live
NVD API, that is right for most application packages and returns *exactly zero*
for the rest — and zero looks identical to "you have no vulnerabilities":

| target | old CPE | old | correct |
|---|---|---|---|
| nginx 1.24.0 | `a:*:nginx` | 2 | 2 |
| OpenSSH 9.6 | `a:*:openssh` | 19 | 19 |
| OpenSSL 3.0.11 | `a:*:openssl` | 32 | 31 |
| MySQL 8.0.35 | `a:*:mysql` | 87 | 87 |
| Apache HTTP Server 2.4.57 | `a:*:apache_http_server` | **0** | 53 |
| Linux Kernel 6.8 | `a:*:linux_kernel` | **0** | 6,582 |
| Ubuntu Linux 22.04 | `a:*:ubuntu_linux` | **0** | 59 |
| Windows Server 2019 | `a:*:windows_server_2019` | **0** | 5,255 |
| Debian 12 | `a:*:debian_linux:12` | **0** | 294 |

Three causes, all now fixed:

- **The part field.** NVD indexes an operating system under `o`. A query that
  says `a` cannot see it, so every OS target reported a clean bill of health.
  The Linux kernel alone accounts for 6,582 CVEs that were invisible.
- **The product token.** "Apache HTTP Server" is indexed as product
  `http_server`; gluing the vendor word into the product finds nothing.
- **The version string.** NVD stores distribution releases with an explicit
  minor. `debian_linux 12` returns 0 CVEs and `12.0` returns 294;
  `enterprise_linux 9` returns 3 and `9.0` returns 595; `centos 7` returns 0 and
  `7.0` returns 2. A bare major version on an operating system now gets its
  `.0`. The rule is confined to operating systems on purpose — `tomcat 9` and
  `tomcat 9.0` both return 14, so applications neither need it nor should be
  disturbed by it.

Names are now resolved through a built-in table plus part inference, so it works
with no network — which matters for an air-gapped install, where the NVD
dictionary resolver is not reachable at all.

**What was *not* the cause, despite being the prime suspect: the wildcard
vendor.** `cpe:2.3:a:*:http_server` returns 53 CVEs against 51 for
`cpe:2.3:a:apache:http_server`, and `o:*:linux_kernel` matches
`o:linux:linux_kernel` exactly at 6,582. The wildcard never lost a CVE and twice
found more, so it stays: a guessed vendor can only narrow the search.

The NVD dictionary resolver had the same two faults at its own layer — it
required a `cpe:2.3:a:` prefix (so no operating system could ever be resolved)
and took whichever entry the keyword search returned first (so a search for a
product could resolve to a plugin for it). It now scores candidates against the
normalised product token and accepts any part.

Measured on the same 25-target estate afterwards: **24 of 25 targets returned
findings, and the 25th was Debian**, whose `.0` rule was written from that
result — so 25 of 25 once it landed. Before, 4 of the 12 targets checked in
detail returned nothing at all.

### Findings no longer carry another product's fix version

A CVE that requires two products present at once lists both in one
configuration — CVE-2019-0190 is the real case, an AND of Apache httpd and
OpenSSL. Version evidence was taken from the first vulnerable `cpeMatch` in the
configuration, so an OpenSSL owner was told their fix version was an httpd
release number. The CVE was right; the evidence was another product's, which is
worse, because the evidence is what someone acts on.

Version evidence now comes only from a `cpeMatch` that names the target's own
product. When a configuration never names it, no version evidence is reported at
all — an empty field is honest, a borrowed one is not.
