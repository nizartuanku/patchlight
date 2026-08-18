# Patchlight

**Self-hosted CVE prioritisation — patch what's exploited and yours, not what's loudest.**

40,000 CVEs a year. Five of them matter to you this week. Patchlight finds those
five. Tell it what you run — type it, paste CPEs, or upload an SBOM — and it
matches every CVE to your real inventory, then ranks the matches by whether
they're actually being exploited (**CISA KEV**), likely to be (**FIRST EPSS**),
and how severe (**CVSS**). You get a short, explained, ranked list — not a wall
of scores.

- **Matches CVEs to your stack** — a CVSS-9.8 in software you don't run is noise; Patchlight filters it out.
- **Ranks by real-world risk** — CISA Known-Exploited + EPSS probability + CVSS, with the numbers shown behind every ranking.
- **The daily diff** — a new CVE that now hits your stack, or one newly added to KEV, surfaces as a change; patched ones auto-resolve.
- **Three ways to load inventory** — product+version (auto-resolved to CPE), raw CPE, or a CycloneDX/SPDX SBOM.
- **Every finding is actionable** — "patch to ≥ x.y.z", with the exploit evidence attached.

> *CVSS tells you how bad a CVE could be. Patchlight tells you which of your CVEs are actually being exploited right now.*

## Self-hosted by design

Runs as a single binary or container on your infrastructure. **Your inventory
never leaves your network** — only CPE queries go to the public feeds (NVD, CISA
KEV, FIRST EPSS), never to us, and you can point them at a local mirror. No
telemetry. License validation is offline cryptography — no phone-home, ever.

## Quick start

```bash
# Docker
docker run -d -p 127.0.0.1:8425:8425 -v patchlight-data:/data patchlight

# Or the bare binary
./patchlight
```

Open `http://127.0.0.1:8425`, add what you run (product+version, a raw CPE, or an
SBOM), and see the CVEs that matter — ranked by exploitation, worst first.

## Feed access

Patchlight reads public vulnerability intelligence and needs outbound access to
it (or a local mirror):

- A free **NVD API key** (https://nvd.nist.gov/developers/request-an-api-key)
  raises the rate limit — pass it with `-nvd-api-key`.
- **Air-gapped?** Point Patchlight at local mirrors:
  `-nvd-cve-url … -nvd-cpe-url … -kev-url … -epss-url …` (each serving the same
  JSON shape as upstream). Only CPE queries are ever sent — never your inventory.

## Editions

| | Free (this repo) | Pro | Team |
|---|---|---|---|
| Inventory items | 25 | 500 | Unlimited |
| Manual + CPE input | ✅ | ✅ | ✅ |
| SBOM import (CycloneDX/SPDX) | ✅ (to the item cap) | ✅ | ✅ |
| KEV + EPSS + CVSS ranking | ✅ | ✅ | ✅ |
| Scan interval | Daily fixed | Custom + scan-now | Custom + scan-now |
| Alert channels | Webhook | + Email, Slack, Telegram | + PagerDuty, MS Teams |
| Offline / air-gapped mirror | — | ✅ | ✅ |
| History | 30 days | 1 year | Unlimited |
| Support | Community | Email | Priority |

Pro ($29/mo) and Team ($99/mo) licenses, each with a 14-day free trial:
**https://whop.com/nizar-tuanku/patchlight-cve-prioritizer**

A license key activates instantly and validates **offline**. An expired key
returns to free limits.

## Honest limits

- Patchlight **prioritises** vulnerabilities; it does not **scan** hosts to
  discover what's installed — you supply inventory (manually, by CPE, or via
  SBOM). Pair it with an SBOM generator for automatic inventory.
- Accuracy depends on NVD's CPE data and your inventory's precision — every
  finding shows the matched CPE and version range so you can sanity-check.
- KEV is curated (not exhaustive); EPSS is a probability. Both are shown as
  numbers, not black-box verdicts.
- Not a patch-deployment tool, and not a replacement for a host vuln scanner — a
  high-signal prioritiser that complements one.

## Built by

A practising network security engineer. Part of the Sentinel line of
self-hosted security tools:
[CertWatch](https://whop.com/nizar-tuanku/certwatch-tls-monitor) (certs),
[Attack Surface Monitor](https://whop.com/nizar-tuanku/attack-surface-monitor) (exposure),
[Decoy](https://whop.com/nizar-tuanku/decoy-canary-honeypots) (intrusion) — and
Patchlight tells you what to patch first.
