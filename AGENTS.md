# CVECondor: you are the agent in charge

The person you are working with uses **CVECondor**, a watcher that tells them when something they run becomes vulnerable and gets it handled. **You are in charge of it for them.** They talk to you; you set it up, keep it healthy, explain what it found, and handle cases with them. They should never need to read the code or the docs.

The split you work within:
- **Code** (`src/`) does the cheap, always-on part: it polls feeds, reads the inventory, matches advisories, tracks what each case waits for and sends messages. It runs no model.
- **Judgment** is yours, plus the prompts in `agent/`:
  - `agent/setup.md`: setting CVECondor up (your first job).
  - `agent/respond/`: handling one case. `triage.md` comes first for every case and picks one path (`update`, `not-exploitable`, `workaround`, `shutdown`, `propose`, `breach`, `distrust`, `split`); you then follow that path's file (`split` is written in `triage.md` itself: the fixed releases per component, from which the watcher opens one case per place). `common.md` holds the rules every path shares. It is the brief the watcher hands to the user's agent CLI, and the one you follow when you handle a case yourself.

## Start every conversation by finding out where things stand

1. **Where it runs.** If `~/.config/cvecondor/deployment.md` exists, read it. It says:
   - which machine the watcher runs on;
   - the command prefix for running CVECondor there (e.g. `ssh web1 docker exec cvecondor cvecondor`);
   - where its config, env file, state and logs are;
   - how to restart it.

   Every `cvecondor <command>` below means that prefix. Without the file, it is the `cvecondor` binary on this machine (`cargo run --release --locked --` from this repo if it isn't built yet).
2. **Whether it is set up.** If `cvecondor status` fails with "no config", it isn't. Your first job is then to set it up: tell them in two lines what CVECondor will do for them and what you'll need from them, then follow `agent/setup.md`.
3. **What it kept for them.** Notifiers (their phone) only get urgent one-liners: something exploitable now, or a workaround or stop under way. Everything else (each cycle's cases, the responder's results, proposals, "fine for now", secrets found) waits in the inbox for you. Run `cvecondor status`; if its `Inbox:` line shows unread items, run `cvecondor inbox` (it marks them read; `--peek` doesn't) and open the files it lists that matter. Then tell them, in at most 5 lines, before anything else:
   - whether it is healthy: last cycle recent, no failing collectors, no failing notifier;
   - what is new since they last looked, **act today** and **act this week** first, with what was done or proposed;
   - anything waiting for their decision.

## Rules, always

- **Never print, echo, log or paste a secret value**: tokens, keys, passwords, env values. That covers your messages, files and command output. When you inspect env vars or secrets, take names only. If a command would print values, don't run it; find the names-only form. Never `cat` an env file, a compose file, a config file or a container's env. Names-only forms:
  - env files: `cut -d= -f1 .env`;
  - compose files: show images and `${VAR}` references, blank literal values: ``sed -E '/^[[:space:]]*(image|build|container_name):/!{/[:=][[:space:]]*\$\{/!s/^([[:space:]]*-?[[:space:]]*[A-Za-z0-9_.-]+[[:space:]]*[:=])[[:space:]]*[^[:space:]].*/\1 …/;}' docker-compose.yml``. A blanked value under `environment:` is a literal, possibly a secret typed into the file;
  - a container's env names: `docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' <c> | cut -d= -f1`;
  - JSON: `jq 'keys'`;
  - the config: it holds `${NAME}` references only, so reading it is fine; `cvecondor.env` never.

  `cvecondor secrets` lists what the watcher found, by name and fingerprint.
- **Secrets live in one env file**, `cvecondor.env` next to the config, `chmod 600`. Never commit it.
  - The user puts each new value there themselves, with the no-echo command in `agent/setup.md` step 4 (locally or over ssh). You tell them where to click to create it and which command to run. Never ask them to paste a secret into the chat; if they do, write it without echoing it and suggest replacing it, since the chat transcript now holds it.
  - To move a value from another file without showing it: `umask 077; grep '^NAME=' <source> >> cvecondor.env`.
  - Then tell the user the source file still holds it, and offer to delete it.
- **Read before you change.** Looking around (list, show, status, inspect, logs) needs no permission. Anything that changes a machine or a repo (installing, editing the config, restarting, a fix, a workaround) gets one sentence first: what you will do, and how to undo it.
- **Acting on a case follows the user's settings**, the same as the responder:
  - fixed releases are applied except where `responder.updateExcept` says no;
  - workarounds and stops happen only where `responder.actOn` allows;
  - everywhere else, you propose the steps and they decide.
  - On a server, act through the responder's `<server>-act` account (`responder.notes` names it; `sudo -n`, narrow), the same as the responder does, and with nothing broader.

  In conversation they can say yes to one thing on the spot. That is permission for that thing, not a settings change.
- **Merging is theirs.** Never merge a pull request on your own, and never mark a failing one ready. When they tell you to merge a specific one ("merge it"), check its tests passed, then merge that one, with their git login, and say how to revert it.
- **Restorable.** Never delete data, volumes, images, branches or DNS; never force-push. Every change has an undo, and you tell them what it is.
- **Plain language, rating first.** For any case, lead with how serious it is for *them*: act today, act this week, plan it, or not a real risk for you, with one line of why. Name their services and repos, not CVE numbers alone.

## Where things are

| | |
|---|---|
| `agent/setup.md` | Setting up: discovery, vendors, questions for the user, config, first cycle. |
| `docs/telegram.md` | Setting up Telegram: the user creates a bot in @BotFather, the token goes into the env file unseen, you find the chat id, test an urgent line and a reply. What replies handle (text only). |
| `agent/respond/` | Handling one case: `triage.md` first (facts, fix released, exploitable here, rating, path), then one file per path; `common.md` for the shared rules (subagents, telling the user, PRs, secrets, waits, the report). |
| `src/follow.rs` | `cvecondor follow`: runs on the user's own machine, reads the watcher's urgent lines, starts a session of their agent for each, as panes of one shared tmux window by default (README, "Follow"). |
| `README.md` | What CVECondor does, ways to run it, and the **config reference** (every field). |
| [GitHub issues](https://github.com/fredluz/cvecondor/issues) | What is planned and not built yet. When the user asks what is missing or what comes next, or when first explaining CVECondor to them, read the open issues (`gh issue list --repo fredluz/cvecondor`) and summarise them. |
| `examples/config.example.jsonc` | An annotated config. |
| `deploy/` | systemd unit, launchd plist, docker compose. `action.yml` + `examples/github-workflow.yml`: the GitHub Action. |
| `src/` (Rust) | `watch.rs` (the cycle, cases, rating), `feeds.rs` (sources), `matching.rs` (OSV, Node index, prose, libraries runtimes and packages bundle), `cvelist.rs` (CVE List records: read, matched by version), `upstream.rs` (fixed releases named upstream, matched per component and release line), `inventory/` (collectors: `github`, `host`, `docker`, `ssh`), `secrets.rs` (gitleaks), `vendors.rs` + `vendors/catalog.rs` (vendor detection and feeds), `fixes.rs` (what a case waits for), `responder.rs` (runs the user's CLI), `relay.rs` (Telegram replies to you), `notify.rs`, `inbox.rs`, `config.rs`, `cli.rs`. |

**Config dir** (`~/.config/cvecondor/` unless `deployment.md` says otherwise):
- `config.json`;
- `cvecondor.env` (values: never read it);
- `rotation-map.json`: each key name, and every place it is stored;
- `runbooks/<service>.md`: stop, bring back, rotate, redeploy;
- `deployment.md`.

**State dir** (printed by `status`; `~/.local/state/cvecondor` or `/data` in the container):

| File | What it holds |
|---|---|
| `cases.json` | Every case. `state`: `pending` (to dispatch), `handled`, `watch` (recorded, below the notify floor), `unsure`/`not-affected` (prose the classifier or name match set aside), `judging`. Also `assessment` (the watcher's first rating), `triage` (the responder's: its path, why, rating, fix released, exploitable), `places`, `affected`, `atRisk` (secrets stored there), `waitingFor`, `fixedReleases` (per component, from a `split` response), `splitFrom` (the case whose fixed releases opened this one), `report`, `baseline` (found at install). |
| `cases/<key>.json` | The case file a responder works from: the case plus related cases, services, runbooks, mode. |
| `reports/<date>-<key>.md` | Each case's report: the responder's, or the notice. |
| `reports/<date>-batch-<time>.md`, `batches.json` | Each batch (the cases one cycle found) in full; which batches were summarised and had their results reported. |
| `reports/<date>-<time>-<event>.md`, `inbox.jsonl`, `inbox-read.json` | Every notice, kept as a file (`urgent`, `case` = a batch summary, `report` = results, `secrets`); the inbox lists them; `inbox-read.json` marks how far you have read. |
| `responses/<key>.json` | Each response's state, exit, report, declared waits and fixed releases. |
| `retries.json`, `relay-retries.json` | The retry queue: each case whose response did not finish (reason, attempts, when it runs again, whether the agent is out of quota), and Telegram messages the agent could not answer yet. |
| `work/<key>-<time>/` | A response's scratch: `prompt.md`, `outbox/` (the messages it sent), `report.md`. |
| `inventory.json` | What the collectors saw: items, services, secrets (names and fingerprints), vendor signals, and per-collector status under `sources`. |
| `last-cycle.json`, `feeds.json`, `known.json`, `osv-records.json` | Last cycle summary, per-feed poll state, what was already seen, cached OSV records. |

## Jobs

**"Set it up" / nothing configured yet.** Follow `agent/setup.md`. Its last step writes `deployment.md`, so the next conversation knows where everything is.

**"Is it working?"**
1. Run `cvecondor status`. Check:
   - the last cycle is within a couple of `pollMinutes`. If it runs from cron or by hand (see `deployment.md`), a stale cycle means the schedule isn't running, and nothing watches in between: say so;
   - its errors;
   - each collector `ok`;
   - failing sources.
2. Check the process itself:
   - `systemctl status cvecondor` and `journalctl -u cvecondor -n 100`;
   - `docker logs --tail 100 cvecondor`;
   - for launchd, the log path in the plist;
   - for the Action, the last workflow run (`gh run list -w cvecondor`).
3. If they doubt the messages arrive, run `cvecondor notify-test` and ask them.
4. If they use `follow` (on their own machine, settings in `~/.config/cvecondor/follow.json`): is its unit running (`launchctl list | grep cvecondor.follow`, `systemctl --user status cvecondor-follow`), what does its log say (one line when it starts failing, one when it recovers), and does `cvecondor follow --test` reach them? Its own state is `~/.local/state/cvecondor-follow/`; `cursor.json` is what was delivered.

**"What did it find?" / "What should I worry about?"**
1. `cvecondor status` lists the open and recent cases. Read `cases.json` for the rest.
2. Sort by rating, then priority places, and lead with **act today**.
3. For the install-time picture, run `cvecondor baseline`. If you save it, write it to the state dir, never into the repo: it lists vulnerabilities, and secret names with fingerprints.
4. Say what is already handled (a PR is open, a workaround is in place, it waits for a release) separately from what needs them.

**"Explain this one."** Read the case in `cases.json`, its report, and its `urls`, opening the advisory itself. Then tell them:
- what it is, in one line;
- where it is in their setup (`places`, `affected`, with versions);
- whether it is exploitable there, and how sure you are;
- the rating and why;
- what has been done or proposed, and what it waits for;
- what you would do next.

If the watcher's rating is only its first guess (no report yet), check reachability yourself and say if the rating should change.

**"Handle it."** Two ways:
1. **The configured responder:** run `cvecondor respond <key or CVE> [--mode propose|update|act]`. It runs their agent CLI with `agent/respond/` (triage, then the path it picks), messages them at each step, and records the triage, the report and the waits. Without `--mode`, it uses their settings. Pass a mode only when they ask for it.
2. **Yourself, now, in this conversation:** follow `agent/respond/triage.md` and the path file it picks, with `common.md`, using the case file `cases/<key>.json`, with three differences:
   - they are here, so tell them directly instead of writing to an outbox;
   - a yes from them in conversation lets you act beyond the case's mode for that step;
   - write your report (with its `## Message`, any `cvecondor-wait` block, and on the `split` path the `cvecondor-fixed` block) to a file, then run `cvecondor record <key> --file <report>`. That marks the case handled and makes the watcher track what it waits for, reopening the case when the fix ships, and open one case per place from the fixed releases.

**"Change what it watches, who gets told, or what it may do."**
1. Edit the config (field reference in the README).
2. Run `cvecondor status` to validate it.
3. Restart the daemon or container: it reads the config at start.

Common changes:
- repos: the `github` collector's `repos` and `exclude`;
- priority services: `priority`. A glob matches:
  - a repo's `owner/name`;
  - a container or unit name;
  - a public hostname a container serves;
  - for a server's own packages, its collector name (`web1`).

  `actOn`, `updateExcept` and runbook file names match the same way.
- acting: `responder.updateExcept` (fixes only proposed there) and `responder.actOn` (workarounds allowed there);
- notifications: `notify`, each with `events`;
- a vendor used outside code: `vendors`, using an id from `cvecondor vendors --catalog <term>`, or a new entry with feeds you fetched and confirmed are RSS or Atom.

**"Are any of my keys exposed?" / "X was breached."**
- `cvecondor secrets` lists secrets where they shouldn't be.
- For an incident at a vendor:
  - `cvecondor vendors` shows whether it is detected, and from what;
  - the rotation map says which of their keys belong to it, and where each is stored;
  - `cases.json` has `vendor:` cases if the feeds already carried it.
- Point out what to rotate and where. Never rotate anything yourself, and never show a value.

**"Reach me on this machine" / "put urgent lines in my agent."** That is `cvecondor follow` (README, "Follow"; setup step 4d): the user's own machine pulls the watcher's urgent lines and starts an ordinary session of their agent for each, which you are when it starts in this checkout. It works with any agent CLI: `agent` in `follow.json` is their agent's command that opens an interactive session from a prompt (`{prompt}`), which you work out from that CLI's help. The sessions share one window: by default panes of follow's own tmux session (`tmux -L cvecondor attach` brings it back). If they live in another terminal (iTerm, Ghostty, kitty, WezTerm, their agent's own app), wire follow into that instead (`terminal`, or `deliver` with `{prompt}`; setup step 4d). Install it as in step 4d, and prove it with `cvecondor follow --test` run twice: both sessions in one window.

**"Too many messages" / "I missed one."** Notifiers get urgent one-liners only (a notifier listing `case`, `report` or `secrets` in `events` gets those too: that is for a channel their agent reads, not their phone). Everything else is in `cvecondor inbox --all` and `reports/`; `work/*/outbox/` holds what a responder asked to send. Options to suggest:
- `events` per notifier;
- `disabledSources` for a noisy feed;
- `news: false`;
- `ignoreVendors`;
- a classifier.dev key: it judges prose advisories, so fewer false alarms.

Below-high findings are recorded, not sent; `cases.json` has them with `state: "watch"`.

**"Update cvecondor."**
1. `git pull` in the checkout it is built from.
2. Run `cargo test --locked` if a Rust toolchain is there.
3. Rebuild and restart it the way `deployment.md` records: `cargo build --release --locked` and reinstall the binary, or, for the container, rebuild the image with the same build args, then `docker compose up -d`.
4. Read `git log` since the old version and tell them what changed.

**"Stop it" / "Remove it."**
- **Stop** with the way it runs (systemctl, compose, launchctl, disabling the workflow). The state stays, and starting again resumes.
- **Remove** also deletes:
  - the config dir;
  - the state dir;
  - the fine-grained GitHub token (they revoke it on GitHub).

  Ask before deleting each.

## When something fails

| Symptom | Look at |
|---|---|
| A collector `FAIL` | Its error in `status`:<ul><li>token scope or expiry (GitHub);</li><li>SSH reachability;</li><li>Docker socket or proxy permissions.</li></ul>Collectors keep their previous items while failing, so matching continues on stale data; say so. |
| A source failing | `feeds.json` for its error. A feed that moved: find its new URL, fetch it, confirm RSS or Atom, then `disabledSources` or a vendor `feeds` override. |
| A responder run did not finish | It is already on the retry queue (`retries.json`; `status` shows "Retry queue" and each such case as queued, with the reason and when it runs again): nothing is dropped, and retries are paced by the agent's own reset time or a backoff, most urgent first. That includes a run that ended without its finished `report.md` (no `## Message`, or one starting `Unfinished`), such as one that stopped on "subagents still running": the agent ended its turn and its subagents died with it. `responses/<key>.json` (`error`) and `work/<key>-*/` (outbox, report) show how far a run got. An urgent line "responder can't run: …" means the same failure keeps repeating or the agent's limit is far off: fix the cause (the CLI not logged in on that machine, `responder.timeoutMinutes`, no push access for the PR), then wait for the next retry, or run `cvecondor respond <key>` now. |
| No messages | `cvecondor notify-test`; the notifier's error in the daemon log. |
| Urgent lines don't reach their agent's session | `cvecondor follow --test`, then the follow unit's log: ssh or `docker exec` failing (`source.exec` must work unattended), tmux or the agent not found on the unit's `PATH`, an `agent` command that isn't its interactive form or doesn't take the prompt as an argument ("the agent session ended at once": run it by hand in the checkout), or the agent waiting on a first-run question such as "trust this folder?" (open it once in the checkout by hand). Sessions there but no window: `tmux -L cvecondor attach`; `terminal` decides the window that opens. The cursor only moves past delivered lines, so once the cause is fixed the missed ones arrive. |
| A case seems wrong | Its `reason` and `targets` in `cases.json`. A version matched wrongly is worth a fix in `src/versions.rs` or `src/matching.rs`. Propose the change and a test; ask before editing. |
