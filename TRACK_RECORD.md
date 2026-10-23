# Track record

What CVECondor has done on the author's own laptop and server since it was switched on (2026-10-22). It lists only what was fixed. Ask your agent to read it alongside the code.

## Check it yourself

You don't have to take the author's word for it. The test suite replays this month's real public feeds (CERT-EU's PHP advisory 2026-018, the Node.js security release of 21 October, Mozilla's eMudhra CA incident, the nginx release of 14 October) against a made-up stack, and asserts that each opens a case naming every place that is affected, running or stopped:

```
cargo test --locked --test replay
```

To see what one replay says, run it yourself against the made-up stack in `examples/replay/` (no network, nothing written outside a temp directory):

```
cargo run --locked -- replay --config examples/replay/replay.config.json --inventory examples/replay/inventory.json \
  --source cert-eu --file tests/fixtures/cert-eu-2026-10-21.xml
```

For each case it prints the places it matches, whether a fixed release exists, how serious it is for that stack, and what mode your agent would run in (update, or propose when there is no fix). Swap `--source` and `--file` for `node-security-blog` / `node-vulnerability-2026-10-21.xml` or `ca-incidents` / `bugzilla-ca-2083449.json`. `--help` lists the rest.

## By the numbers

| | |
|---|---|
| Feeds and databases watched | 46, polled every 5 minutes |
| Time from an advisory being published to a case being opened | median 15 minutes |
| Advisories set aside because the classifier judged they didn't apply | handled without spending an agent run |
| Every fix | tested before and after, with the results written in the report or the PR |

## Fixes it made

**A container that renews TLS certificates: BIND 9.20.29 → 9.20.30** (CVE-2026-19630, CVE-2026-94300, CVE-2026-96888, CVE-2026-97313). The agent read the container rather than the advisory titles: only BIND's client tools were installed, not the DNS server, so three of the four had no code path. A fixed package existed but the upstream image hadn't been rebuilt, so it built a three-line local image on top of it, recreated only that container, and checked that the restart policy, network and mounts matched, that a certificate issuance in flight completed, that every site answered as before and no certificate went missing.

**A workaround before the patch, then the patch** (CVE-2026-111497, Brotli out-of-bounds write in the Bun runtime). No fixed release existed and the decoder was reachable from any response with Brotli encoding, so a request-level guard went into the affected client-facing containers that morning. When Bun 1.4.4 shipped, the containers were rebuilt on it, staging first, and the guard came out. Three endpoints returned the same status and body hash before and after.

**nginx, updated although nothing was exploitable** (CVE-2026-15176, CVE-2026-93479, CVE-2026-95101, CVE-2026-97629, CVE-2026-97205). Each needs a specific feature; the agent read every config and none was switched on. A fix existed, so it updated anyway. One image had no fixed official build: it rebuilt it from the upstream project, tried it in a throwaway container against every site's status, redirect and body hash, then swapped it in.

**A dependency fix tested against the results from before the change** (CVE-2023-54404, zod memory exhaustion, in a video pipeline). No fixed 3.x existed and five nested copies were pinned older, so it moved everything to 4.6.7 with an override, then ran each check on the old branch and the new one: typecheck, scenario checks, 12 rendered images byte-identical, a 90-frame render the same, speech-to-text on a clip giving the same words and timings. Merged after the owner's go.

**A merged fix PR covering 25 advisories** in a Python and TypeScript app, one of them flagged as exploited in the wild. The PR said what changed and that the test results matched the base branch exactly (45 pass, the same 5 pre-existing failures), and the owner merged it.
