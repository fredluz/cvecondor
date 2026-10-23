# Triage: the first thing for every case

Follow `common.md` throughout. Establish the facts below through subagents, in parallel, each bringing back evidence: one for what the sources say (1 and 3), one per place for 2 and 4. Then pick one path, write it down, and follow that path's file. Minutes, not hours.

## The facts

1. **What the sources say.** Read the advisory at its sources: affected products and versions, fixed versions (released or only announced, with the time), exploitation in the wild, the vendor's workarounds. If a page won't load, use the vendor's own advisory, a mirror, or OSV (`https://api.osv.dev/v1/vulns/<id>`), and say which.
2. **Affected here?** The version actually in use is in range: the lockfile on the default branch, the image tag and its runtime version, `dpkg-query -W <pkg>` or `<binary> --version` on a server you can reach. When the vendor says "all versions", count it as affected.
3. **Is a fix released, in the artifact the user runs?** A fixed release that exists today. If the artifact that carries it doesn't exist yet (an official image not rebuilt on the fixed runtime, an image that bundles the server and has no release with the fixed version; check the tag's runtime version), there is no fix yet.
4. **Exploitable here?** Only when no fix is released (with a fix, don't spend time proving exploitability: update). Are the trigger conditions present: the vulnerable feature enabled, the configuration that exposes it, the function actually called, an input an attacker can reach (a public endpoint, an upload, a parser fed by users)? Is it reachable from outside (public hostname, published port, reverse-proxy route, firewall)? Check it now; there is no stored exposure map. A trigger condition that is absent, or that you cannot establish, means not exploitable.
5. **How serious for this user**: the rating (`common.md`).
6. **In `actOn` or not**: the mode under "This case".

Read `related` in the case file and the reports it names: if the same issue was handled this week and nothing changed, the path is `already-handled`. A **REOPENED** case means the fix it waited for has shipped: the path is `update` (it also removes the workaround).

## Pick the path

Take the **first** row that matches, top to bottom: a breach or a CA incident takes its own path even when fixed releases exist.

| Situation | Path |
|---|---|
| Version not in range | `not-affected`: a short report saying why, change nothing, send nothing, stop |
| A vendor case (`case.kind` is `vendor`) whose sources show no incident at that vendor: it is only named (another company's breach, an attack that used its service or stolen tokens for it), or the item is advice, research, a bug bounty or security program, or a plain outage | `not-affected`: a short report saying whose incident it is, send nothing, stop |
| Handled this week, nothing changed | `already-handled`: a short report naming the earlier one, send nothing, stop |
| A vendor that holds the user's keys was breached (`case.kind` is `vendor`), or a malicious package version (a `MAL-` alias) | `breach.md`, even when a clean version exists (it covers that) |
| A certificate authority is compromised or distrusted (the case title starts with "CA incident", or its source is `ca-incidents`) | `distrust.md`, even when fixed bundles exist: it covers those updates, and every other trust store, too |
| Fix released, mode UPDATE or ACT (or REOPENED) | `update.md` |
| Fix released, mode PROPOSE | `propose.md` |
| No fix, not exploitable here | `not-exploitable.md` |
| No fix, exploitable here, mode ACT | `workaround.md` (it hands over to `shutdown.md` only if nothing narrower removes the risk) |
| No fix, exploitable here, nothing narrower than a stop removes the risk, mode ACT | `shutdown.md` |
| No fix, exploitable here, mode UPDATE or PROPOSE | `propose.md` |

A case grouping several advisories in one place (`aliases`, `waitingFor`) where some have a fix: `update.md` for those, and it sends the rest back through question 4.

## Write it down

Write `triage.json` in your working directory, then follow the chosen file. The watcher records it on the case:

```json
{"path": "workaround", "why": "one line: the fact that decided it", "rating": "act today", "fixReleased": false, "exploitable": "yes"}
```

`path` is one of `update`, `not-exploitable`, `workaround`, `shutdown`, `propose`, `breach`, `distrust`, `not-affected`, `already-handled`. `exploitable` is `yes`, `no`, `unknown` or `not checked` (a fix exists). If what you find later changes the path (a workaround turns out not to be possible), update `triage.json` and say so in the report.
