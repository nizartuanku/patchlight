# Sample run

This is real Patchlight output, not a mockup. Two real-world CVEs — Apache
HTTP Server 2.4.49 and Apache Log4j 2.14.1 — were registered on a lab
instance of the free edition as CPE targets, matched for real against the
live NVD, CISA KEV, and FIRST EPSS feeds, and the findings exported exactly
as the API returned them — nothing in
[`sample-findings.json`](sample-findings.json) or
[`sample-summary.json`](sample-summary.json) was hand-edited.

**Source:** a lab instance of Patchlight 0.1.3, free edition, with AI Assist
turned off so this sample shows the matching engine on its own, not a
model's narration. The two targets are two of the most well-documented,
publicly disclosed CVEs in CISA's Known Exploited Vulnerabilities (KEV)
catalog — chosen precisely because anyone can verify the matches
independently against NVD. No customer inventory is reproduced here.

## What was registered

| Target (CPE 2.3) | What it's built to demonstrate |
|---|---|
| `cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*` | the 2021 path-traversal/RCE pair (CVE-2021-41773 / CVE-2021-42013) that put Apache httpd 2.4.49 on CISA's KEV catalog within days of disclosure |
| `cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*` | Log4Shell (CVE-2021-44228) — the single most consequential Java CVE of the decade |

Free tier allows 150 inventory items — this sample uses 2, confirmed by
`GET /api/summary` in `sample-summary.json` (`"targets":2,"max_targets":150`).
Both targets got their first scan immediately on registration — free tier's
fixed 12-hour interval governs *re*-scans, not the first one ("five minutes
to first value", per `sched.Scheduler.AddTarget`).

## What Patchlight found

**98 open findings total: 5 critical, 13 high, 59 medium, 21 low** — the
exact counts in `GET /api/summary`.

| Target | CVE | Priority | KEV | EPSS | CVSS | Severity |
|---|---|---|---|---|---|---|
| `apache:http_server:2.4.49` | CVE-2021-41773 | P1 | ✅ 2021-11-03 | 1.00 | 9.8 | **critical** |
| `apache:http_server:2.4.49` | CVE-2021-42013 | P1 | ✅ 2021-11-03 | 1.00 | 9.8 | **critical** |
| `apache:http_server:2.4.49` | CVE-2024-38475 | P1 | ✅ 2025-05-01 | 1.00 | 9.1 | **critical** |
| `apache:log4j:2.14.1` | CVE-2021-44228 (Log4Shell) | P1 | ✅ 2021-12-10 | 1.00 | 10.0 | **critical** |
| `apache:log4j:2.14.1` | CVE-2021-45046 (Log4Shell follow-up) | P1 | ✅ 2023-05-01 | 1.00 | 9.0 | **critical** |
| `apache:http_server:2.4.49` | CVE-2021-41524 | P3 | — | 0.25 | 7.5 | medium |

All 5 critical findings are on CISA KEV (confirmed exploited in the wild),
which is exactly why Patchlight ranks them P1 ahead of the other 93 — see
`sample-findings.json` for all 98 rows with full evidence.

httpd 2.4.49 alone carries 88 of the 98 findings and log4j 2.14.1 the other
10 — both are genuinely old, unpatched point releases, so the real NVD
dataset returns every CVE that has ever matched that exact version string,
not a curated handful. That is the product working as designed: *"CVSS
tells you how bad a CVE could be, Patchlight tells you which of your CVEs
are actually being exploited right now"* — of httpd's 88, only 3 are on
CISA KEV; of log4j's 10, only 2 are (Log4Shell itself and its incomplete-fix
follow-up, CVE-2021-45046). All 5 KEV hits are ranked P1, strictly ahead of
the other 93 findings regardless of raw CVSS score.

Log4Shell's finding carries `"fixed_version":"2.3.1"` and
`"version_range":"≥ 2.0.1, < 2.3.1"` taken straight from the NVD advisory —
Patchlight's remediation text (`"Patch apache log4j 2.14.1 to ≥ 2.3.1."`) is
generated from that same field, not written by hand.

## Reading the evidence honestly

Every finding carries the advisory text NVD actually returned for that
match — CVE ID, CVSS vector, the live EPSS probability, the KEV listing date
when present, and the fixed-version range — in `evidence` in
`sample-findings.json`. Nothing is summarized away.

This sample does not show SBOM import (CycloneDX/SPDX), the "daily diff"
feature (a new CVE or a newly-patched one surfacing as a *change* needs two
scans over time — this is one point in time), on-demand scan-now, or
multi-channel notification (webhook/syslog on free; email/Slack/Telegram/
PagerDuty/Teams on Pro/Team) — those exist and are covered by the engine's
own unit tests (`sched/scheduler_test.go`, `patchlight/patchlight_test.go`);
this sample is a real run against two real, named CVEs, not a tour of every
feature.
