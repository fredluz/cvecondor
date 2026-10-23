![CVECondor: watches what you run for CVEs; your agent checks if you're exposed; updates it, or codes a workaround.](assets/cover.png)

# CVECondor

CVECondor will inventory the apps and packages you’re running, and watch for released vulnerabilities so you don’t have to doomscroll twitter. When it finds a vulnerability, it will dispatch an agent running on your local CLI (i.e. Codex, Claude Code) and have that agent evaluate if you are vulnerable and if so fix it. It can either update the apps and packages or code a workaround fix while there is no patch.

You can install CVECondor by pointing your agent at this repo. Just send it the link https://github.com/fredluz/cvecondor and it will read the context we have prepared for it. CVECondor is made to be highly customizable and adaptable to your own workflow.

TRACK_RECORD.md is a file containing what CVECondor has done on my Mac + VPS since I’ve built it, you can point your agent to it and it’ll tell you if it’s worth installing or not.

Below this is a long description of the program that Claude wrote. I haven’t read it, I don’t think you need to either. Just ask your agent to go through it and tell you the important parts.

> Licensed under Apache-2.0.

CVECondor tells you when something you run becomes vulnerable, before you read about it on social media, and gets it handled.

**Don't take our word for it: point your own agent at this repository.** It reads every file, `TRACK_RECORD.md` included (what CVECondor has fixed, and how to check it yourself), and can tell you what CVECondor does, then set it up for you (see "Quick start" below).

- **Watch.** Every few minutes it polls public sources: CISA's exploited list, the CVE List (every new and updated CVE record), CERT-EU, OSV (GitHub advisories, PyPI, npm, distro trackers, malicious packages), the Node, PHP and Python security announcements, Bun's releases, Mozilla's CA incidents, your vendors' status pages and security bulletins, and general security news. Unchanged feeds cost one `304`. No model runs while nothing new matches.
- **Match.** It matches the advisories against an inventory of what you run:
  - your GitHub repos: lockfiles, manifests, Dockerfile and compose base images, runtime version files;
  - optionally your servers: host packages, containers, their OS packages and runtimes, Python virtualenvs.
  - What carries a library built in (Node and Bun carry Brotli and zlib, Python wheels carry OpenSSL or libxml2) is matched when an advisory names the library. When the sources name fixed releases before OSV maps every ecosystem, your agent reads them per component and the watcher opens one case per place from them, each with the release it moves to.
  - It also matches vendor incidents (a hosting platform breach has no CVE) against the vendors it detects you use: their own feeds, and news whose headline names them. With a responder, your agent confirms a vendor incident and your exposure before anything is pushed.
- **Secrets.** It points out secrets that could be compromised: committed `.env` files and credential files in repos, world-readable env files on servers, tokens printed in container logs. When a vendor or a place is hit, it lists which of your keys and env vars live there and need rotating. It shows names, places and an 8-hex fingerprint, never values, and it never rotates anything itself.
- **Rate it for you.** Every case and the install baseline say how serious it is *for you*, not just the CVSS label: **act today**, **act this week**, **plan it**, or **not a real risk for you**, with one line of why (exploited in the wild, running, publicly reachable, what is at stake).
- **Respond.** Critical, high and exploited findings, and reported vendor incidents, get a response, including what was already vulnerable when you installed it; lower is recorded, not notified.
  - **Your phone only hears what can't wait.** Telegram, Slack, email or a webhook get one short line, and only when something is exploitable now or the responder is working around it or stopping something: what, where, what is being done. Nothing else is pushed.
  - **Everything else waits for your agent.** Each cycle's cases (the install baseline is one batch, **act today** and **act this week** in full on top, the rest counted per repo or service), the responder's results for the batch, proposals, "fine for now", secrets found: each is a file under `reports/` and a line in the inbox. When you open your agent, it reads the inbox (`cvecondor inbox`) and tells you in a few lines. If your agent can also be reached somewhere else (a chat it reads, a command that drops a message in its inbox), a notifier with `events: ["case", "report", "secrets"]` delivers there.
  - **With a responder,** CVECondor hands the case to **your own agent CLI** (Claude Code, Codex, omp, or any command) with a standing brief. The CLI runs logged in with your subscription, never an API key. It triages first (is a fix released, is it exploitable here, how serious for you, may it act), records the path it picked on the case, then follows that path's brief. It works through subagents, and what it found and did goes into the batch's report.
  - **A response that doesn't finish is retried, never dropped.** A run is finished only when the agent has written its `report.md` with a `## Message` (and that message doesn't start with `Unfinished`); the brief tells it to wait for its subagents and write the report last, since a headless run that ends its turn kills the subagents still working. Whatever the cause (the agent's usage limit, an error, a timeout, a missing or logged-out CLI, a run that ended on "subagents still running" without its report), the case goes on a retry queue (`retries.json` in the state dir) with the reason; `status` and the inbox show it as queued, not failed. It runs again after the reset time the agent names ("resets 7:40pm (UTC)" from Claude, "try again at …" or "in 2h 31m" from others), else after a backoff of 5 minutes doubling to 3 hours. While the agent says it is out of quota, nothing starts, new cases included. The queue drains within `maxPerCycle`, most urgent first (exploited, then act today, act this week, plan it), so a reset does not fire everything at once. A newer event for a queued case replaces its retry. A cause that won't fix itself (the same failure three times, or a limit that resets more than 6 hours away) is said once as an urgent line ("responder can't run: …"), never on every retry, and a retry never repeats an urgent line the run before it sent. Messages sent to the Telegram relay that the agent can't answer are kept the same way and answered late, once it can.
  - **A fix exists:** it updates, batched per host and per repo: on a server it pulls or upgrades and recreates only what changed, keeping the old image for a rollback; in a repo it opens a tested pull request with your own git login, and never merges it. It checks the service still works, and tells you.
  - **No fix yet:** it confirms whether the vulnerability is exploitable on your system (trigger conditions, reachable input, exposure). Not exploitable: it tells you "you'll need to update, but you're fine for now" and tracks the fix. Exploitable: it tells you at once and works around it (guard, disable, block, pin; a restorable stop only as a last resort). When the fix ships, the case reopens so the update goes in and the workaround comes out.
  - **Defaults:** applying a fixed release is on (switch it off per service with `updateExcept`, or entirely with `updateWhenFixed: false`). Working around an exploitable problem, or stopping a service, is a per-service opt-in (`actOn`); everywhere else you get exact commands, diffs, verification and undo. What was already there at install is assessed and proposed, unless it is exploited in the wild.

## Quick start: talk to your agent

CVECondor comes with an agent in charge of it. Open the agent CLI you already use (Claude Code, Codex, omp, or another) in a clone of this repo, and talk to it. It reads `AGENTS.md` (Claude Code reads it through `CLAUDE.md`; with a CLI that doesn't load either, say "read AGENTS.md"), which tells it what CVECondor is, where everything lives, and how to run it.

- **The first time,** it sets CVECondor up (`agent/setup.md`). It:
  - finds your repos, servers and vendors with the access you already have;
  - asks you only for what it can't find (a token, where to send messages, what it may act on);
  - writes the config, starts the watcher and shows you what is already vulnerable.
- **After that,** ask it anything: "is it working?", "what should I worry about?", "explain the PHP one", "handle it", "stop messaging me about news", "add our Workspace account". It reads the state, explains cases in plain language, runs the responder or handles a case with you, and changes the config with your OK.

By hand, if you prefer. CVECondor is built from source, on the machine where it runs (Rust 1.88+ and a C compiler; `ring`, its TLS crypto, compiles C):

```sh
git clone https://github.com/fredluz/cvecondor && cd cvecondor   # examples/ and agent/ come with the clone
cargo install --path . --locked   # puts `cvecondor` in ~/.cargo/bin
brew install gitleaks   # or your package manager; optional, enables secret scanning
mkdir -p ~/.config/cvecondor && cp examples/config.example.jsonc ~/.config/cvecondor/config.json
$EDITOR ~/.config/cvecondor/config.json                 # keep the github collector, delete what you don't use
bash -c 'umask 077; read -rs -p "GITHUB_TOKEN: " T; echo; printf "GITHUB_TOKEN=%s\n" "$T" >> ~/.config/cvecondor/cvecondor.env'
# prompts without echo; cvecondor.env next to the config is loaded automatically; variables already set win
cvecondor inventory      # what it sees
cvecondor baseline       # what is vulnerable or exposed today
cvecondor notify-test    # does the message reach you
cvecondor cycle          # one full cycle; then run it on a schedule (below)
```

Wherever it runs, the env file holding the secrets sits next to the config, outside the checkout, readable only by the user CVECondor runs as. It never goes into a container's environment (`env_file`, `environment`): CVECondor reads it from the mounted config dir.

**The GitHub token:** create a fine-grained personal access token (Settings → Developer settings → Fine-grained tokens) for the repos to watch, in one of two shapes:
- **One token (simplest):**
  - Contents and Pull requests: read and write. Metadata: read-only.
  - The watcher only reads with it.
  - The responder gets it as its gh/git login, through `"responder": { "env": { "GH_TOKEN": "${GITHUB_TOKEN}" } }`, to open fix PRs.
- **Separate (stricter):**
  - The watcher's token is read-only: Contents and Metadata.
  - The responder acts with its own login, so a compromise of the watcher alone can't write.

Optional, either way: Secrets read-only (Actions secret names, for breach impact) and Deployments read-only (detects Vercel, Railway, Netlify…).

## Ways to run

| | Command | Notes |
|---|---|---|
| Container | `CVECONDOR_CONFIG_DIR=<config dir> docker compose -f deploy/docker-compose.yml up -d --build` | One container, built from this checkout with the static binary (`cvecondor run` is its default command). The config dir (config and env file) is mounted read-only at `/config`. On a server, the compose file also covers the server: the host's `/` is mounted read-only, and containers are read through a GET-only socket proxy. State lives in the `/data` volume. Add what a responder needs with `--build-arg AGENT=<name>`: git and `gh` for any value, plus the agent CLI itself for `claude` or `codex`; for any other CLI, extend the image and set `responder.command`. Claude Code's login there is `CLAUDE_CODE_OAUTH_TOKEN`, from `claude setup-token` run on any machine with a browser, passed on through `responder.env`. |
| Daemon (Linux) | `deploy/systemd/cvecondor.service` | Runs `/usr/local/bin/cvecondor run` as an unprivileged `cvecondor` user. Config and env file in `/etc/cvecondor`; the unit's comment lists what must be true. |
| Daemon (macOS) | `deploy/launchd/com.cvecondor.plist` | For an always-on Mac. A laptop that sleeps pauses the watch. |
| GitHub Action | `examples/github-workflow.yml` + `action.yml` | Runs on a schedule (every 15 min; GitHub may delay it). Builds CVECondor from the action's source once and caches the binary; state persists in the Actions cache. `agent: claude` or `codex` installs the responder's CLI. Covers repos and SSH hosts, not the runner itself. |
| Follow (your own machine) | `deploy/launchd/com.cvecondor.follow.plist`, `deploy/systemd/cvecondor-follow.service` | Not the watcher: `cvecondor follow` runs where you sit and brings the watcher's urgent lines into an ordinary session of your agent (see below). |
| Cron | `cvecondor cycle` | Each run refreshes a stale inventory and waits for responders to finish. |

## Commands

```
run                 daemon: a cycle every pollMinutes, inventory every inventoryHours
cycle               one cycle now; waits for responders
inventory [--out F] refresh the inventory now (read-only)
baseline [--out F]  critical/high per place today, secrets where they shouldn't be, vendors watched
status              last cycle, sources, collectors, open cases
vendors             the vendors detected (and named in the config); --catalog [TERM] lists catalogue ids
secrets             secret findings: names, places, fingerprints
notify-test         a test line through every notifier
inbox [--all] [--peek]
                    what was kept for you (everything not urgent) since you last read it; then marks it read
replay --source ID --file F [--only TEXT] [--inventory FILE] [--respond]
                    replay a feed document against your inventory (or the inventory file given) in a throwaway state dir;
                    prints each case's rating, fix and the mode your agent would run in; --respond runs your agent
respond KEY [--mode propose|update|act]
                    run the responder on one case now (a lower-severity case, or a mode you choose; failed runs retry by themselves)
record KEY --file REPORT
                    record a case handled in conversation: its report, what it waits for (fix tracking), and the fixed releases it names
follow [--once | --test] [--config FILE]
                    on your own machine: each urgent line from the watcher opens a session of your agent
```

## Follow: urgent lines in your agent's own session

A watcher on a server can't reach the agent on your laptop, so the laptop pulls. `cvecondor follow` runs on the machine you sit at (macOS or Linux) and, every minute, reads the watcher's new urgent lines through the same access `deployment.md` records (an ssh prefix, a `docker exec`, or a local state dir). Each line becomes an **ordinary interactive session of your own agent**, whichever CLI that is, started in your CVECondor checkout, so it loads `AGENTS.md` and is the agent in charge: it tells you what the line is, and you answer it like any chat ("what is this?", "do it", "merge it": a pull request is merged only when you say so). It is not a headless one-shot.

- **Delivery.** `agent` is your agent's command that opens an interactive session from a prompt, with `{prompt}` where the opening message goes (`["claude", "{prompt}"]`; `claude`, `codex` and `omp` are shorthands for that form, any other CLI is its own argv). By default follow owns one tmux session (its own tmux server: `tmux -L cvecondor attach` reattaches) and every delivery starts a new agent session in it as a **pane of one shared window** (tiled; once it holds four, the next goes in a new window of the same tmux session), with the line as its opening message. `"layout": "windows"` gives each a window instead; `"layout": "one"` keeps one agent session and types later lines into it (a bracketed paste, so the text can't act as keystrokes). A terminal window is opened on the tmux session only when none is attached (macOS Terminal, or a Linux terminal found on PATH, or your own `terminal` argv with `{attach}`), so sessions never mean one new window each; with one attached, focus stays where you are typing and a click picks a pane. tmux is the one mechanism that works for every agent CLI and terminal. For your own terminal's panes or tabs, or an agent with its own "send to my session" command, set `deliver` to that command (`{prompt}` is the opening message, `{line}` the line alone) and follow only runs it.
- **Once, across restarts and sleep.** A cursor in `~/.local/state/cvecondor-follow/` moves only past what was delivered, so a failed delivery (ssh down, no tmux, the agent won't start) is retried on the next poll, and a restart never repeats anything. The first run starts after what the inbox already holds. Lines older than a day, or more than five at once, become one summary line.
- **Desktop notification** per line too (`osascript` / `notify-send`), so a line is seen even with the session window behind. `"notification": false` turns it off.
- **Set up** with `examples/follow.example.jsonc` → `~/.config/cvecondor/follow.json`, then `cvecondor follow --test` (a test line through the real delivery) and the launchd/systemd unit in `deploy/`. `dir` is the folder you set CVECondor up in with your agent, so it is already trusted. Your agent works out its own `agent` command (or `deliver`) and proves it with `--test` (`agent/setup.md` 4d).
- Lines are text from public feeds typed into an agent that can run commands: the opening message tells the agent to treat them as data. Keep the agent's permissions as you would for any session in that checkout.

## Config reference

One JSON file (comments allowed): `--config`, `CVECONDOR_CONFIG`, or `~/.config/cvecondor/config.json` (or `config.jsonc`). `examples/config.example.jsonc` shows every option.

- **Secrets** are `${ENV_VAR}` references, resolved at start; a missing one is an error, not an empty credential. Put the values in `cvecondor.env` next to the config (`chmod 600`): it is loaded automatically. Every variable in that file or read by the config is removed from the responder's environment and redacted from logs, notices and reports.

| Key | Default | Meaning |
|---|---|---|
| `collectors` | required | `github`, `host`, `docker`, `ssh` (below) |
| `priority` | `[]` | Globs for the repos (`owner/name`), containers, units and hostnames whose users are your customers, and servers by collector name (`web1`) for their own packages. They lead every case and message. `actOn`, `updateExcept` and runbook names match the same way. |
| `classifier` | from `CLASSIFIER_API_KEY` | classifier.dev with your key. It judges prose advisories and vendor news. Without a key, plain name matching decides. `{ "anonymous": true }` uses classifier.dev's free anonymous tier instead, with its limits. `false` turns it off. |
| `responder` | off | `command`: your agent CLI's argv. One array for every mode, or `{ "propose": [...], "update": [...], "act": [...] }` (a mode you leave out uses `act`, then `update`, then `propose`). Placeholders, replaced anywhere inside an argument: `{prompt}` (path of the full prompt file; when no argument has it, the prompt goes on stdin), `{brief}` (the standing brief, copied into the work dir as `brief.md`), `{case}` (the case file), `{report}` (where to write the report), `{workdir}`, `{mode}` (`propose`, `update` or `act`). `agent` is optional shorthand: a preset (`claude`, `codex`, `omp`) used only when `command` is absent (with `command` set it is just a label). `updateWhenFixed` (on: apply fixed releases everywhere) with `updateExcept` (globs that only get proposals); `actOn` (globs where it may work around an exploitable problem with no fix, last resort a restorable stop); `env` (variables it gets by name, e.g. `"GH_TOKEN": "${GITHUB_TOKEN}"`, `"CLAUDE_CODE_OAUTH_TOKEN": "${CLAUDE_CODE_OAUTH_TOKEN}"`: it inherits none of the watcher's secrets otherwise); `reach` (shell commands the responder runs itself to put an urgent line in front of you, the line on stdin, besides the notifiers: e.g. a command that posts to the chat your agent reads; in propose mode they are the only shell it gets); `notes`, `brief` (a directory like the shipped `agent/respond`: `common.md`, `triage.md`, one `<path>.md` per path), `maxPerCycle` (2), `timeoutMinutes` (60), `cwd`. |
| `notify` | `[]` (inbox only) | `telegram` (`botToken`, `chatId`, optional `replies`: true makes the watcher read the user's messages from that chat and have the agent in charge, the responder's `act` command, answer them; needs a `responder`, and the bot must be CVECondor's own because the watcher is its only reader), `slack` (`webhookUrl`), `email` (SMTP `host`, `port`, `security`: `tls`/`starttls`/`none`, `user`, `pass`, `from`, `to`), `webhook` (`url`, `headers`; JSON body), `command` (argv; the notice text on stdin, `NOTICE_EVENT`/`NOTICE_TITLE`/`NOTICE_KEY`/`NOTICE_REPORT` in its env; exit 0 means delivered). `events`: `urgent` (the default: one short line, only for something exploitable now or a workaround or stop under way), and `case`, `report`, `secrets` (summaries, results, secret findings) for a channel your agent reads. Every notice also lands in `reports/` and the inbox. |
| `vendors` / `ignoreVendors` | `[]` | Vendors to add by hand (ids from the catalogue, or your own with `feeds`), or to ignore. |
| `news` | `true` | General security news, matched to your vendors when the headline names one (a vendor named only in the summary is usually another company's incident). |
| `disabledSources` | `[]` | Sources not to poll, by id: `cisa-kev`, `cve-list`, `cert-eu`, `node-security-blog`, `node-security-index`, `php-news`, `nginx-news`, `bun-releases`, `python-blog`, `ca-incidents`, `osv:<ecosystem>` (`osv:npm`, `osv:PyPI`, `osv:Debian`, …), `news:<name>` (`news:krebs`, …), `vendor:<vendor id>:<feed kind>`. `feeds.json` in the state dir lists every id polled. |
| `rotationMap` / `runbooks` | none | Written at install: each key → where it is stored; per-service runbooks. The responder gets the matching ones. |
| `pollMinutes` / `inventoryHours` | 5 / 1 | Cadence. |
| `stateDir`, `timezone` | `~/.local/state/cvecondor`, system | State and report dates. |

Collectors (all read-only):

- **`github`**: `token`, `repos` (globs; empty means every repo the token can read), `exclude`, `includeForks`, `includeArchived`, `maxFileBytes`, `apiUrl` (GitHub Enterprise).
  - **Reads:** the default branch's lockfiles (npm, bun, pnpm, yarn, pip, uv, poetry, Cargo, Go, Composer, Bundler), exact pins in manifests, Dockerfile `FROM` and compose `image:` (with their runtime versions), `.nvmrc`/`.python-version`/`.tool-versions`, deploy configs (`vercel.json`, `fly.toml`, `wrangler.toml`, …), deployments, and Actions secret names.
  - **Image env:** for each image those files name, it reads the image config's env from the registry (anonymous pull token, no pull; only `*_VERSION` variables are kept). A bundled server's version (`NGINX_VERSION` in nginx-proxy) or a runtime's (`NODE_VERSION`, `PHP_VERSION`, `PYTHON_VERSION`, `BUN_VERSION`, `RUBY_VERSION`, `GOLANG_VERSION`) becomes a runtime of that repo, as it does for a running container. Answers are kept for 24 hours; at most 40 registry lookups per collection; a registry that cannot answer is a warning on the collector, never a failure.
  - **Scans for secrets:** committed env and credential-prone files, with gitleaks.
  - **Cost:** unchanged repos cost no requests beyond the repo list (image env: none inside 24 hours).
- **`host`** (a Linux server; on a Mac, use `github` and `docker`): `name` (how messages name the server, e.g. `web1`), `root` (`/`, or `/host` from a container), `binaries`.
  - **Reads:** the dpkg or apk database, runtime versions, and the packages of Python virtualenvs in those project dirs (the dir itself, `.venv`, `venv`; names and versions from `*.dist-info`).
  - **Scans for secrets:** compose and `.env` files under systemd working dirs, `/opt`, `/srv`, `/home/*/*` and `/root/*` (names and fingerprints only; world-readable files are flagged).
- **`docker`**: `name`, `endpoint` (`unix://`, `tcp://`, `https://` with `tls`), `exec` (off).
  - **Reads (GET only):** per container, its OS packages and the lockfiles in its working directory through the archive API (stopped containers too), runtime versions from image env (or, for an official runtime image that sets none, such as `oven/bun`, the version its tag names), published ports and `VIRTUAL_HOST`.
  - **Scans for secrets:** env secrets (names and fingerprints), and log tails.
- **`ssh`**: `host`, `port`, `identityFile`, `sshOptions`, `sudo`, `docker`, `timeoutSeconds`.
  - **Access:** `sudo: true` runs the reads through `sudo -n`, so its rule needs `cat`, `find`, `stat` and `sed` (and `docker` with `docker: true`); version probes run without sudo. A refused `docker ps` is a warning on the collector, not an empty server.
  - **Reads:** one read-only script per refresh, covering the host collector's reads plus containers via `docker inspect`/`docker cp … -` (never `exec`), their logs, and compose dirs.

## Status: v0.1

What it covers today, and what is new. What CVECondor has fixed so far, and how to check it yourself, is in [`TRACK_RECORD.md`](TRACK_RECORD.md).

- **Today:** it watches your GitHub repos (lockfiles, manifests, base images, runtime versions) and optionally your servers against the public sources above, rates each match for you, and hands critical, high and exploited ones to your agent CLI, which triages and then proposes, updates (tested pull requests, never merged) or works around.
- **New in 0.1:** the CVE List as a source; a retry queue for agent runs that don't finish (usage limit, error, an unfinished report); vendor incidents confirmed by your agent before anything is pushed; `cvecondor follow`, which pulls urgent lines to another machine.
- **Tested on:** macOS (arm64); CI runs the test suite on Linux and macOS. The test suite includes a replay of three real incidents (PHP, Node and eMudhra, Oct 2026) through the whole pipeline. The host, docker and ssh collectors have also run against a real Ubuntu 24.04 VM.
- **Install:** from source (`scripts/release.sh` builds static binaries into `dist/`); there are no release binaries or images yet.

What it covers and what it doesn't is listed in the next section.

## What's covered, and what isn't

**Covered:**
- npm, PyPI, Go, crates.io, Packagist and RubyGems dependencies in your repos.
- Base images and their runtimes.
- Ubuntu, Debian and Alpine packages on hosts and in containers.
- Node by semver from the Node security index.
- Product CVEs from the CVE List ([cvelistV5](https://github.com/CVEProject/cvelistV5)), by version: PHP, nginx, appliances and anything outside OSV's ecosystems, as long as the record gives a version range for a runtime, image or package you run. Records that only name a product (free-text or git/rpm versions) go through the name match and classifier like a prose advisory, never straight to a case. A CVE another source already opened joins that case. CISA's ADP container in the record adds severity and "exploited". Cost: one conditional Range request on `cves/deltaLog.json` (the repository's log of every publisher run, newest first, 30 MB: only its first bytes are read; a `304` when no run happened, a few KB otherwise), then each changed record's own file (about 9 KB, at most 300 per poll; the rest wait for the next poll). The first read only records where the log stands. A distro's own package (Debian, Ubuntu, Alpine) is judged from OSV, because upstream ranges ignore backported fixes; the CVE List only makes it a candidate for the classifier.
- PHP, Python and Bun announcements, and CERT-EU and CISA KEV by product name. A Bun release whose notes name a security fix counts as one, as Node's and PHP's posts do.
- Libraries that runtimes and packages carry built in (Brotli, zlib, zstd, OpenSSL, SQLite, V8, … in Node, Bun, Deno and Python and npm binary packages; the table is `BUNDLED` in `src/matching.rs`): an advisory or CVE record naming the library reaches what carries it, marked `bundles <library>`, as well as the library's own distro package.
- Fixed releases named before every database maps them. The CVE record, a vendor's release notes and the news name fixed versions days before OSV maps each ecosystem. The responder reads them per component (each runtime's release lines, each language package, each distro's own package) and takes the `split` path; the watcher then opens one case per place, each showing the release it moves to, a separate "move to a supported line" case for a line that gets no fix, and no case for what is already on a fixed release. It keeps matching them every cycle, so what is deployed later is found too.
- CA compromises (all TLS clients).
- Malicious packages.
- Incidents at about 160 catalogued vendors (hosting, clouds, GPU/model hosting, AI APIs, databases, auth, payments, email, observability, CI, secret managers), when you use them. An item about a vendor comes from its own feeds or a news headline that names it; one whose headline is a CVE is a product advisory, left to the CVE List and OSV. With a responder, every vendor case goes to it first: it reads the sources and checks your exposure, and only it sends an urgent line. Without one, a classifier-confirmed incident with keys of yours stored there is Act today. The keys listed are the vendor's own, the CI secrets and secret-named env vars of places that deploy on it, and the rotation map's.

**Not covered (v1):**
- Installed apps on your own laptops and desktops (v2).
- Apple security releases (only the Apple CVEs CISA lists as exploited come through).
- RHEL/Fedora/Arch/Homebrew packages (no OSV ecosystem queried).
- Maven/NuGet dependencies.
- Floating image tags beyond the version their tag names.
- Git history (a secret committed and later deleted is not searched for).
- A standing exposure map: the responder checks exposure itself when a case runs.
- Application-level versions inside images (WordPress core, plugins, themes): only the image's OS packages, runtimes and lockfiles are read.
- Python virtualenvs inside containers: only the lockfiles in the working directory, and with `exec` on, the system interpreter's `pip list`.

## Design: code for the always-on part, prompts for judgment

**Code** does the cheap part that has to run every few minutes:
- polling feeds;
- reading inventories;
- matching advisories and newer versions against them;
- tracking what each case waits for;
- relaying messages.

It runs no model, except classifier.dev as an optional cheap filter for prose.

**Prompts run by your own agent** carry everything that needs judgment:
- `AGENTS.md`: the agent in charge. It knows the tool, the files, the state, and how to check, explain, change and handle things.
- `agent/setup.md`, its first job: finding your repos, servers, vendors and their feeds, building the rotation map and runbooks, and choosing what may act.
- `agent/respond/`: one case. `triage.md` comes first (the advisory at its sources, whether a fix is released, whether it is exploitable on your system, the rating, the path); then one brief per path: `update`, `not-exploitable`, `workaround`, `shutdown`, `propose`, `breach`, `distrust`. Its `split` path writes, per component, the fixed releases the sources name, and the watcher opens the cases from them. `common.md` holds what every path shares: subagents, telling you as it goes, how it reaches servers, pull requests never merged by the responder, no secret ever shown, waits and the report.

The watcher's own rating of each case is a first guess from what it can see (exploited, running, exposed, at stake). The responder replaces it.

## Roadmap: v2, installed apps on your own machines (design only)

A collector per machine (macOS first) lists installed apps and how each updates, and the same split applies:
- **Code:** list apps and versions, and poll each app's release source for a newer version.
- **Prompt:** read the release notes and decide.

- **Package-managed apps and the OS:** `brew outdated`, `mas outdated`, `softwareupdate --list`. When an update exists, the responder applies it like any fixed release: `brew upgrade`, `mas upgrade`, or, for OS updates that need the user's password or a restart, an exact instruction to the user.
- **Self-updating apps:** the code finds each app's release history:
  - its Sparkle appcast (`SUFeedURL` in `Info.plist`);
  - its GitHub releases;
  - the vendor's release-notes page;
  - Homebrew cask metadata (version, homepage, `livecheck` source).

  When a newer version appears, the agent reads its notes. If they mention a security fix, it tells the user to update (apps that auto-update usually need only a relaunch).
- **Exploitable with no fix:** the agent blocks the app, telling the user first: it quits the app and keeps it from relaunching (the login item and LaunchAgent disabled restorably), or, where Santa is deployed, adds a block rule. Each step has an undo.
- **Apps as vendors:** each installed app counts as a vendor for breach detection. A breach at the vendor names the user's keys and accounts tied to it, such as API keys in the app's config, browser-extension tokens, and the accounts it is logged into (names and places only, like the rest).

## Safety model

- **Collectors only read.** With the stricter token shape, each collector's credentials (the GitHub token, the SSH key, the Docker socket or proxy) are separate from anything the responder uses to act. With one token, the watcher still only reads with it.
- **The responder runs as your CLI**, with your login, in a scratch directory. Its environment never inherits the watcher's secrets: it gets only what `responder.env` passes by name.
- **What it may do is set per service:** fixed releases are applied except where `updateExcept` says no; workarounds and stops happen only where `actOn` says yes. Everything else is proposed.
- **On a server it acts through its own narrow account, not the collectors'.** The collectors stay read-only (the host mounted read-only, Docker through a GET-only proxy). The responder reaches the server over `ssh` as a separate `cvecondor-act` account whose `sudo -n` allows only the package manager's upgrade, the service manager and Docker (the header of `deploy/docker-compose.yml` and `deploy/systemd/cvecondor.service` lists what must be true). Docker access is root-equivalent: whoever controls the responder's agent controls the server. Without that account, server steps come to you as exact commands.
- **It tells you before and after each workaround or stop**, one line each; updates and proposals go in its report. It never deletes data, images, branches or DNS. It never pushes to a default branch or merges, and never rotates keys. A pull request is merged only when you tell the agent in charge to.
- **Secret values are never stored, logged or sent.** gitleaks output is read in memory, and each value becomes an 8-hex fingerprint.

## Development

```sh
cargo test                                  # matching, the cycle, collectors, notifiers, responder, and a replay of the Oct 20-22 2026 PHP, Node and eMudhra incidents
cargo clippy --all-targets -- -D warnings
scripts/release.sh                          # static binaries into dist/ (macOS arm64 + Linux x86_64/arm64 musl, no Docker), to copy to a server that can't build
```

## Licence

Apache-2.0, see `LICENSE` and `NOTICE`. The Docker image also ships gitleaks (MIT).
