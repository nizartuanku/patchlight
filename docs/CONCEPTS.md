# Patchlight — Concepts

What this product is, what problem it solves, and why it works the way it does — written for
someone meeting the problem for the first time. The command reference is in the README; this
is the reasoning behind it.

*Hexward Labs · Nizar Tuanku — Cybersecurity. · last reviewed 6 September 2026*

---

## Forty thousand a year
Roughly forty thousand new CVEs are published every year. If you run a small estate — a couple of web servers, a database, a few Linux boxes, some network gear — a few thousand of those will technically apply to something you own, and a scanner will happily list every one of them with a severity score attached.
Nobody patches a list of three thousand items. What actually happens is that the list gets sorted by CVSS score, the top few are patched, and the rest wait. That sounds sensible until you learn that CVSS measures how bad a vulnerability could be, not whether anyone is using it. A 9.8 that no attacker has ever bothered to exploit sits above a 7.5 that is being used against companies like yours this week.
Patchlight exists to swap that ordering for one that reflects the real world.
## Three words you will see on every finding
**CVSS** is a 0-10 score for how severe a vulnerability would be if exploited. **EPSS** is a probability, published by FIRST and updated daily, that a given CVE will be exploited in the next 30 days. **KEV** is CISA's short, curated list of vulnerabilities known to be exploited right now.
None of the three is enough alone. KEV is small and lags. EPSS is a probability, not a fact. CVSS is a ceiling, not a forecast. Patchlight uses all three, in a fixed order, and shows you the numbers behind every ranking so you can disagree with it.
## Four buckets, in order
- P1 — on KEV and in your inventory. Somebody is exploiting this, and you run it. Patch this week.
- P2 — likely next. EPSS at or above 50%, or a critical CVSS with real exploitation probability behind it.
- P3 — plan it. Serious on paper (CVSS 7 or higher) with low exploitation signal. Goes into the next maintenance window.
- P4 — matched, low signal. Keep for the record; do not lose sleep.
The rule that decides the bucket is one short function with no hidden weights. It is the same for everyone, and it is printed in the technical document.
## "In your inventory" is doing most of the work
The reason most vulnerability tooling produces noise is not the scoring — it is that the scoring is applied to everything, including software you do not run. Patchlight starts from the other end: tell it what you have, and it only ever talks about CVEs that match.
You can type in a product and version, paste a CPE string if you already have one, or upload an SBOM from your build pipeline. Patchlight turns each entry into the exact identifier the vulnerability database uses, and matches from there.
## Which brings us to the honest part
That identifier step is where a tool like this can quietly fail, and Patchlight did. Its first release turned "Linux Kernel 6.8" into a database query that returned zero vulnerabilities. Same for "Apache HTTP Server", "Ubuntu 22.04", "Windows Server 2019" and "Debian 12". The correct answers were 6,582, 53, 59, 5,255 and 294.
The causes were small and specific — the database files operating systems under a different letter than applications, expects "http_server" rather than the full product name, and stores "Debian 12" as "12.0". None of that is visible from the outside. What is visible is a clean report, and a clean report and a broken lookup look identical.
The fix shipped in release 0.1.1 on 6 September 2026, measured at 25 of 25 test targets returning findings. The lesson survived the fix and is now written into the product's own documentation: if a target shows zero findings, that is the one to open first and check that the identifier matches what the database actually uses. Patchlight shows that identifier on every target precisely so you can.
We tell you this because a prioritiser you cannot verify is just a different-shaped opinion.
## The daily diff
Once your inventory is loaded, Patchlight re-checks it on a schedule — every 12 hours by default. What it reports is not the whole list again but what changed: a new CVE that now hits something you run, or an existing CVE that has just been added to KEV — which is the moment a "plan it" item becomes a "this week" item. When you patch, the finding resolves itself. The list you read is the list of things that are different from yesterday.
## Nothing leaves your network except a product name
Patchlight runs on your own host as a single binary. The only outbound traffic is the lookup itself — a product identifier sent to the public vulnerability feeds — and if even that is too much, every feed can be pointed at a local mirror, on every edition including the free one. Nothing is sent to Hexward. There is no telemetry, and the licence key is checked by cryptography on the machine, not by phoning anyone.
## What it will not do
- It does not discover what you run. You supply the inventory. If you want it automatic, generate an SBOM and feed that in.
- It does not deploy patches. It tells you which ones matter and why.
- It does not know about back-ported fixes. If your distribution patched a package but kept the upstream version number, Patchlight will still match it. Every finding shows the version range so you can check.
- It is not a replacement for a host scanner. It is the layer that decides, out of everything a scanner might find, which five to do first.
## Try it
The free Apache-2.0 edition on GitHub carries the full ranking, the diff, and webhook and syslog alerts. Release 0.1.1 caps the inventory at 25 items; the next release raises that cap to 150. Make sure you are on 0.1.1 or later — the earlier build is the one with the resolver defect described above, and it is marked superseded.
```
curl -LO https://github.com/nizartuanku/patchlight/releases/latest/download/patchlight-free-0.1.1-linux-amd64.tar.gz
curl -LO https://github.com/nizartuanku/patchlight/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS
tar xzf patchlight-free-0.1.1-linux-amd64.tar.gz && ./patchlight
```
Pro (500 items, custom schedule, Slack/Telegram/email) and Team (unlimited, PagerDuty/Teams) are on Whop; Whop sells paid licences only.
Nizar Tuanku — Cybersecurity. · github.com/nizartuanku/patchlight

## Terms used above

- CVSS — a 0-10 score for how severe a vulnerability would be if exploited. Published with the CVE. Says nothing about likelihood.
- EPSS — a probability, from FIRST, that a given CVE will be exploited in the next 30 days. Updated daily. Says nothing about whether it affects you.
- KEV — CISA's list of vulnerabilities that are known to be exploited. Short, curated, and the strongest single signal available.
