# Setup: your first job as the agent in charge

You are setting CVECondor up for the person you work for (`AGENTS.md` says who you are; its rules apply throughout). Work through the steps in order. Use only the access you already have: their shell, their logged-in CLIs, their SSH config. Ask them only for what you cannot find. When you ask, ask everything you need in one go, and say why you need each answer.

When you finish, they should have:
- a watcher running on an always-on machine;
- a first cycle done;
- `~/.config/cvecondor/deployment.md` on this machine (step 7), so you can find it again in later conversations;
- a short summary from you.

Two more rules while setting up:
- **Discovery is read-only.** Every command you run to learn about their setup reads: list, show, status, inspect. Never deploy, restart, change permissions or edit their services, except to install the watcher itself where they agreed.
- **Never hand the watcher a broad token**, even one lying around (`gh auth token`, a classic PAT). It gets the fine-grained token from step 4, scoped to the watched repos.

## 1. Prerequisites (check, then install what is missing with their OK)

- **The machine it runs on.** Ask which machine is always on: a server they reach (a VPS, a home server), or a Mac or Linux box that stays on and logged in. A laptop is a poor fit: when it sleeps, the watch pauses.
- **How it runs there:** a container, a plain daemon (systemd, launchd), cron, or the GitHub Action for repos only (README, "Ways to run"). Pick with them from what the machine already has: Docker there makes the container simplest. Work out the install yourself from the shipped files; what must be true is below and in each file's header comment.
- **The `cvecondor` binary, built from this repo's source** on that machine (there are no published binaries or images):
  - **Plain daemon:** a Rust toolchain 1.88 or newer (`rustup`, or the distro's `cargo` if new enough), a C compiler (`build-essential` or `clang`: `ring`, the TLS crypto, compiles C) and git; then `cargo build --release --locked` in a clone. About 1–2 GB of disk and RAM for the build. A server too small to build gets a static musl binary built elsewhere (`scripts/release.sh`: on a Mac it builds both Linux targets, on Linux the native one) and copied over; check its checksum after copying.
  - **Container:** Docker with compose, and the clone on that machine; `docker compose build` compiles inside the image, no Rust on the host.
  - Check it with `cvecondor --version`.
- **git**; **gitleaks** for secret scanning (`brew install gitleaks`, `apt install gitleaks`, or gitleaks' release binary with its checksum; the container image has it). Without gitleaks everything else still works, and `inventory` warns "gitleaks is not installed: secret scanning skipped".
- **With a responder** (4b), where CVECondor runs and as the user it runs as: the agent CLI itself, logged in; git and `gh`, with git pushing through gh (`git config --global credential.https://github.com.helper '!gh auth git-credential'`), so the `GH_TOKEN` in `responder.env` is its git login for fix branches and pull requests. The image adds these with `--build-arg AGENTS="claude codex omp"` (any subset; git and gh for any `AGENTS` value, and `AGENT=<one>` still works); a plain daemon needs them installed.
- **This repo** on the machine you talk to them from: the docs and the responder brief (the binary also carries the brief).
- **Secrets, wherever it runs:** `cvecondor.env` sits next to the config, outside any git checkout, readable only by the user CVECondor runs as. It never goes into a container's environment (`env_file`, `environment`), a unit's `Environment=`, or the repo.
- **Acting on the server** (with a responder, when CVECondor covers a server). The responder updates there by default, and works around or stops only on `actOn` services, so it needs a way to change the server that the collectors don't have. What must be true, for either deployment (the headers of `deploy/docker-compose.yml` and `deploy/systemd/cvecondor.service` say the same):
  - a separate host account, `cvecondor-act`, with no password, reached over `ssh` from where the responder runs (the container reaches the host as `host.docker.internal`; the daemon reaches `localhost`) with a key used only for this, its host key pinned in a `known_hosts` the responder reads;
  - its `sudo -n` allows only: the package manager's update and upgrade (`apt-get update`, `apt-get install --only-upgrade`; `apk update`, `apk upgrade`), `systemctl` stop/start/restart/enable/disable/status, and `docker`; never a shell, an editor or `sudo -i`;
  - the arguments are pinned, not wildcards, wherever an argument could be an option or a path (each was shown to give root on a test server): `apt-get install --only-upgrade *` also takes `-o DPkg::Pre-Invoke::=<command>`, so allow named packages, or a regex rule (sudo 1.9.10+) that admits package names only; `systemctl enable *` also takes a unit file path the account can write, so list the units by name (`systemctl restart nginx.service`), never `*`. `docker` can't be narrowed this way (`compose up` and `run` mount `/`), so the account is root-equivalent through it anyway;
  - a workaround in a server config file (a reverse-proxy rule) needs that file group-writable for `cvecondor-act`, and the service's runbook names it;
  - `responder.notes` says how to reach it: "Act on web1 with `ssh web1-act` (container: `ssh -F /config/ssh/config web1-act`); privileged commands as `sudo -n`."

  Tell the user what this costs before you set it up: Docker access is root-equivalent, so whoever controls the responder's agent (its login, its prompt) controls the server; the sudo list keeps a mistake narrow, not an attacker. Setting it up changes their server (a user, a key, a sudoers file): it needs their OK and their sudo, and its undo is removing those three. Without it, the responder proposes every server step as exact commands. It is checked in step 7.8.

## 2. Learn what they run (read-only)

**Their repos.** With `gh` if it is logged in: `gh repo list <owner> --limit 200 --json nameWithOwner,isArchived,isFork,pushedAt`. Do this for the user and each org they belong to (`gh api user/orgs --jq '.[].login'`). Propose a repo list: active, non-archived, their own forks only if deployed. Note which repos deploy where (look for `vercel.json`, `fly.toml`, `railway.json`, `wrangler.toml`, `Dockerfile`, compose files, `.github/workflows/*deploy*`).

**Without `gh`** (not installed or not logged in): ask for their GitHub username and the organisations whose repos matter, then either:
- they name the repos to watch, and you write them in `repos`; or
- they pick the repos on GitHub's token page in 4a (it lists every repo the owner has), and you leave `repos` empty: an empty list means every repo the token can read, so the token's selection is the watch list.

Once the token exists, `cvecondor inventory` reads the repos, and `inventory.json` in the state dir lists each one's items (`where`: `repo:<owner>/<name>`), deploy configs and deployments among them; finish the notes above from there.

**Their logged-in CLIs** (skip the ones that aren't installed or logged in; names only, never values):

| CLI | Read-only commands |
|---|---|
| `vercel` | `vercel project ls`, `vercel env ls` (names) |
| `railway` | `railway list`, `railway status`; variables by name only, e.g. `railway variables --json \| jq 'keys'` |
| `fly` | `fly apps list`, `fly secrets list -a <app>` (names and digests) |
| `aws` | `aws sts get-caller-identity`, `aws lambda list-functions --query 'Functions[].FunctionName'`, `aws ecs list-clusters` |
| `gcloud` | `gcloud projects list`, `gcloud run services list` |
| `gh` | `gh secret list -R <repo>` (names), `gh api repos/<repo>/deployments --jq '.[].environment'` |
| `netlify`, `wrangler`, `supabase`, `doctl` | their equivalent `list` and `status` commands |

From this, write down for the summary: what is actually deployed and where, and which deployments look dead. Dead means no deploy in months, a failing or empty URL, or a project nobody's repo deploys anymore. **Point those out; don't touch them.** If you can't tell where something runs (no deployments, no platform CLI), say so and say what would tell you.

**Their servers.** If they reach a VPS (`~/.ssh/config` hosts, or they tell you), look with their access, read-only:
- the OS (`cat /etc/os-release`);
- `docker ps -a --format '{{.Names}} {{.Image}} {{.Status}}'`;
- compose project dirs (`docker inspect -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}'`);
- what is public (reverse-proxy hostnames, published ports).

That is how you will describe the services in steps 5 and 6.

## 3. Their vendors

CVECondor ships a catalogue of about 160 vendors (`src/vendors/catalog.rs`): env var names, config files, SDK packages, image names, deployment bots, and verified status and security feeds. At runtime it detects the vendors the user uses and watches only those. Your job is the list it can't detect:

1. From step 2, list the vendors you see: cloud, hosting, AI APIs, databases, auth, payments, email, observability, CI, registrars, password managers, workspace tools. Use the catalogue ids where they exist: `cvecondor vendors --catalog <term>` searches the catalogue.
2. For each vendor **not** in the catalogue, find its status page and security or advisory feed. Many status pages serve `/history.rss` or `/history.atom`; others serve `/feed.rss`, `/feed` or `/rss`. **Fetch each candidate URL and confirm it returns RSS or Atom** before you propose it. If none works, propose the vendor without feeds: news matching still covers it.
3. Show the user the list: detected vendors (they will be watched automatically), vendors added by hand, and feeds you verified. Ask for accounts used outside code that you couldn't see, such as Google Workspace or Microsoft 365, password managers, domain registrars, Notion, Linear or Figma.
4. Put the confirmed additions in `vendors`:
   - catalogue ids as plain strings;
   - `{ "id", "name", "aliases", "feeds": [{ "url", "kind": "status" | "security" }] }` for new vendors;
   - for a catalogue vendor with no feed, its id with your verified `feeds`: they are added to the catalogue entry, and detection still applies.

## 4. Ask the user (one message), then walk them through the logins

Ask only what you couldn't find:

1. **The GitHub token shape** (section 4a creates it). Offer the two and let them choose:
   - **One token (simplest).** The watcher only ever reads with it. The responder gets it as its gh/git login, through `"responder": { "env": { "GH_TOKEN": "${GITHUB_TOKEN}" } }`, to push fix branches and open PRs. The cost: whoever compromises the watcher's machine can write to those repos. That is true of the responder's login anyway, if both run in one place.
   - **Separate (stricter).** The watcher's token is read-only. The responder acts with its own login on that machine (`gh auth login` as the user who runs it, or a second token in `responder.env`). A compromise of the watcher alone can't write.
2. **A classifier.dev key** (optional; section 4e puts it in). Say what it does and what they lose without it: it judges the written advisories (CERT-EU, vendor bulletins, CVE records that name a product without version ranges, security news) and vendor incident posts against what they run. Without it, plain name matching decides: a prose advisory naming something they run opens a case even when it doesn't apply, and every vendor post or headline that names one of their vendors with an incident word opens a vendor case (and, with a responder, a run on their subscription to check it). Nothing is missed either way; the difference is noise. Three choices: their own key (best), `"classifier": { "anonymous": true }` (classifier.dev's free anonymous tier, rate-limited, no account), or none (leave `classifier` out).
3. **Every way urgent things can reach them** (section 4c: their agent's own chat, desktop notifications, phone push, Telegram, Slack, email, a webhook; urgent goes to all of them, never one alone), and **where else they talk to their agent**, if anywhere besides this CLI. Tell them the rule first: only urgent things are pushed, one short line each (something exploitable now, or the responder working around or stopping something: what, where, what is being done). Everything else waits for their agent: you read it when they open you and tell them in a few lines.
4. **Where it runs** (step 1), if not settled.
5. **Which services are client-facing.** They become `priority`, which puts them first in every message. `priority` globs match:
   - a repo's `owner/name`;
   - a container or systemd unit name;
   - a public hostname a container serves (`VIRTUAL_HOST`);
   - for a server's own packages (OpenSSL, OpenSSH), the server's collector name. A client-facing server is listed by that name.
6. **How the responder may act.** Tell them how it works, then ask the two questions:
   - **When a fixed release exists, it updates automatically.** It applies the update without investigating, batched per host and per repo (one pull request per repo, opened with their own git login and never merged by it; you merge one when they tell you to), checks the service still works, and tells them. This is on by default. Ask which services, if any, should only get a proposal instead; they go in `responder.updateExcept`.
   - **When no fix exists, it first checks whether the vulnerability is exploitable on their system.**
     - If it isn't, they hear "you'll need to update, but you're fine for now" with why, and the watcher tracks the fix.
     - If it is, they are told at once, and the responder works around it (guard, disable the feature, block the path, pin the dependency; a restorable stop only as a last resort).
     - Ask which services it may do that on without asking; they go in `responder.actOn`. Everywhere else it proposes the exact steps and runs none. The default is nothing.

   On a server, both need the act account (step 1, "Acting on the server"); ask whether they want it.
7. **The responder** (optional): the agent system they already use, run headless with their own subscription or login (section 4b). Usually that is you, the agent doing this setup. Not a new pay-per-token API key.

Then create the env file and walk them through each login below, one at a time. **They do the clicks and the pasting; you tell them exactly what to click and which command to run.** Never ask them to paste a token, key or password into the chat. If they paste one anyway, write it to the env file without echoing it, and tell them it now sits in the chat transcript, so creating a new one and revoking that one is safer.

### Getting a value into the env file without it showing

The env file is `cvecondor.env` next to the config (`~/.config/cvecondor/cvecondor.env` by default), outside any git checkout. In the end it must be readable by the user the watcher runs as and nobody else: `chmod 600` owned by that user (for the container, uid 1000), or `0640` with that user's group. Create it empty first, as that user: `umask 077; touch <config dir>/cvecondor.env`. If you can only write it as another user (the ssh login user, while the watcher runs as a dedicated `cvecondor` user), fix its owner afterwards with their OK (that needs their sudo), and check with `ls -l`, never by reading it.

For each value, give them this command with `NAME` and the path filled in. It prompts without echoing, so the value never appears on screen, in shell history or in a process list. It runs in `bash` explicitly because zsh's `read -p` means something else.

- **The env file is on the machine they are typing on:**
  ```sh
  bash -c 'umask 077; read -rs -p "NAME: " T; echo; printf "NAME=%s\n" "$T" >> ~/.config/cvecondor/cvecondor.env'
  ```
- **The env file is on a server** (they type on their laptop; the prompt is local, the value travels inside ssh):
  ```sh
  bash -c 'read -rs -p "NAME: " T; echo >&2; printf "NAME=%s\n" "$T"' | ssh <host> 'umask 077; cat >> <config dir>/cvecondor.env'
  ```

Then check it by name only: `cut -d= -f1 <config dir>/cvecondor.env` (prefixed with `ssh <host>` for a server). Each name should appear once. If a paste went wrong (empty, twice, or the wrong value), remove that line without showing it, then run the recipe again:
```sh
umask 077; grep -v '^NAME=' cvecondor.env > cvecondor.env.new; mv cvecondor.env.new cvecondor.env
```
A token that was printed on their screen when they created it (GitHub's page, `claude setup-token`) is gone once they close the page or clear the terminal (Cmd-K or `clear`); suggest they do.

### 4a. The GitHub token (fine-grained)

Tell them to open github.com and click:
1. Their profile picture (top right) → **Settings** → **Developer settings** (bottom of the left sidebar) → **Personal access tokens** → **Fine-grained tokens** → **Generate new token**. (Direct link: `https://github.com/settings/personal-access-tokens/new`.)
2. **Token name:** `cvecondor`. **Description:** "CVECondor: reads dependencies; opens fix PRs" (or "reads dependencies" for the read-only one).
3. **Resource owner:** the account or organisation that owns the watched repos. One token covers one owner: repos under several owners need one token each, as separate `github` collectors (`GITHUB_TOKEN_ACME`, …). An organisation may need to approve the token before it works, or may not allow fine-grained tokens at all; if so, an org owner approves it under the org's Settings → Personal access tokens → Pending requests.
4. **Expiration:** one year is a good balance (organisations may cap it). Write the expiry date into `deployment.md` (step 7); GitHub emails them before it expires, and an expired token shows as a failing `github` collector in `status`.
5. **Repository access:** **Only select repositories**, then pick each repo from the list you agreed in step 2. Not "All repositories": a new repo is then added here, and to the config, on purpose.
6. **Permissions** → **Repository permissions** (Add permissions), each with why:

   | Permission | One token | Read-only (separate) | Why |
   |---|---|---|---|
   | Contents | Read and write | Read-only | read lockfiles, manifests, Dockerfiles; with write, the responder pushes fix branches |
   | Pull requests | Read and write | (none) | the responder opens fix PRs |
   | Metadata | Read-only | Read-only | added automatically; lists the repos |
   | Secrets | Read-only (optional) | Read-only (optional) | Actions secret **names** only, never values; tells breach impact which keys live in CI |
   | Deployments | Read-only (optional) | Read-only (optional) | where each repo deploys (Vercel, Fly, …), for exposure and vendors |

   Leave everything else at "No access". A write token can push branches but cannot bypass branch protection; the responder never merges.
7. **Generate token**, copy it, and run the env-file recipe with `NAME` = `GITHUB_TOKEN`.

Revoking it later: the same Fine-grained tokens page → the token → **Delete**.

### 4b. The responder: hook up the agent they use

The responder is any agent that can run headless (no one at the keyboard) with a prompt, use tools (read files, run commands, write files), and exit when done. CVECondor runs it per case with a standing brief, in a scratch directory, on the machine where CVECondor runs. It logs in the way the user already pays for it (a subscription, or whatever login they use that agent with), and its usage counts there. Don't add a pay-per-token API key just for this.

**Work out how to run yourself headless** (or the user's agent, if they prefer another):
1. Find out what you are, from your own environment: the process that runs you (`ps -o comm=,args= -p $PPID`, walking up if that is a shell), your CLI's name and version, and the env vars your harness sets. If that doesn't name one CLI (a wrapper or daemon runs you, or the env names several), ask the user: "Which agent CLI do you use, and is it logged in with your subscription? (Claude Code, Codex, omp, other)". Their answer decides; they may also prefer an agent other than you.
2. From that CLI's own help (`<cli> --help`, its docs), find:
   - its non-interactive mode, which takes a prompt and exits (often `-p`/`--print`, `exec`, `run`, or a prompt on stdin);
   - how it gets the prompt: a file argument, an `@file` reference, or stdin;
   - how it allows tools without asking (a permission mode, an auto-approve or sandbox-bypass flag), since nobody can approve a step;
   - how it logs in on a machine without a browser or in a container (a long-lived token, a device-code login, a credentials file you can copy, an export/import command);
   - whether it needs anything in the image (its package, a shell such as `bash`).
3. Write it as `responder.command`: the argv, with `{prompt}` where the prompt file's path goes (without `{prompt}`, the prompt comes on stdin). `{brief}`, `{case}`, `{report}`, `{workdir}` and `{mode}` are also replaced (the brief file, the case file, the report path, the scratch dir, `propose`/`update`/`act`). One argv serves every mode, or give `{ "propose": [...], "update": [...], "act": [...] }`. The command runs in the scratch directory (or `responder.cwd`), with the user's environment minus every secret the watcher reads, plus what `responder.env` passes by name (its login token, `GH_TOKEN`). It must exit 0 when done, within `responder.timeoutMinutes`.
4. Get its login onto the machine where CVECondor runs, without the value showing (the env-file recipe above, or the CLI's own login command run there), and pass it in `responder.env` if it is an env var.
5. Prove it in step 7 with one propose-only response (`respond <key> --mode propose`): it must read the case, write a report with a `## Message`, and change nothing. If it fails, `responses/<key>.json` and the `work/<key>-*/` dir say how far it got.

Three agents have presets (`"agent": "claude" | "codex" | "omp"`), with a tighter tool set in propose mode. They are examples of what the steps above produce, not a list to choose from; anything else goes in `command`. The presets run exactly these (from `src/responder.rs`; the prompt goes on stdin unless the argv has `{prompt}`):

| Agent | `propose` | `update` and `act` |
|---|---|---|
| claude | `claude -p --output-format text --permission-mode acceptEdits --allowedTools Read,Grep,Glob,Write,Edit,WebFetch,WebSearch,Task --disallowedTools ScheduleWakeup,Monitor,CronCreate` (plus `Bash(<cmd>:*)` for each `responder.reach` command) | `claude -p --output-format text --dangerously-skip-permissions --disallowedTools ScheduleWakeup,Monitor,CronCreate` |
| codex | `codex exec --sandbox workspace-write --skip-git-repo-check -` | `codex exec --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check -` |
| omp | `omp -p --no-session --tools read,grep,glob,write,edit,task,web_search @{prompt}` | `omp -p --no-session @{prompt}` |

`update` and `act` run with the CLI's full access as the user CVECondor runs as, which is why that user's access is what bounds it (step 1).

- **Claude Code** (`"agent": "claude"`; a Claude Pro or Max subscription):
  1. On any machine with Claude Code installed and a browser (their laptop is fine), they run `claude setup-token`.
  2. It opens the browser to log in to their Claude account and authorise the token, then prints a long-lived OAuth token in the terminal (it starts with `sk-ant-oat01-`). It is tied to their subscription, not billed per use.
  3. They copy it and run the env-file recipe with `NAME` = `CLAUDE_CODE_OAUTH_TOKEN`, then clear the terminal.
  4. The config passes it to the responder by name: `"responder": { "env": { "CLAUDE_CODE_OAUTH_TOKEN": "${CLAUDE_CODE_OAUTH_TOKEN}" } }`. In a container, build the image with `claude` in `--build-arg AGENTS=`.

  This works the same on a server, in a container or in the GitHub Action (its `agent: claude` input installs Claude Code on the runner; the token goes in the repo's Actions secrets). If CVECondor runs as a plain daemon under a user that has already run `claude` and logged in interactively, that login also works and no token is needed.
- **Codex** (`"agent": "codex"`; a ChatGPT plan that includes Codex):
  - **Plain daemon:** as the user CVECondor runs as, on that machine, they run `codex login --device-auth`. It prints a URL and a one-time code (neither is a secret); they open the URL on any device, log in to ChatGPT and enter the code. If it says device-code login is off, they turn it on in ChatGPT's security settings, or run `codex login` on their laptop and copy `~/.codex/auth.json` to the same path on the server with `scp` (it is a credential: `chmod 600`, never `cat` it).
  - **Container:** the login must live on the data volume. Build with `codex` in `--build-arg AGENTS=`, run the login once inside it, and point the responder at it:
    ```sh
    docker compose run --rm --entrypoint sh cvecondor -c 'mkdir -p /data/codex && CODEX_HOME=/data/codex codex login --device-auth'
    ```
    and `"responder": { "env": { "CODEX_HOME": "/data/codex" } }`.
- **omp** (`"agent": "omp"`; its login is a file under its home, `~/.omp/agent/agent.db`, whichever provider it logs in to):
  - **Plain daemon:** as the user CVECondor runs as, on that machine, `omp login` (pick the provider their subscription is with) and follow its prompts. If the machine has no browser, copy the login from their laptop instead, without it showing: `omp auth export | ssh <host> omp auth import -`. That copies every login stored on the laptop; tell them so before they run it.
  - **Container:** the login must live on the data volume. Build with `omp` in `--build-arg AGENTS=`, log in once inside it with `HOME` on `/data`, and point the responder at it:
    ```sh
    docker compose run --rm --entrypoint sh cvecondor -c 'mkdir -p /data/omp && HOME=/data/omp omp login'
    # or copy a login from a machine that has one:
    omp auth export | docker compose run --rm -T --entrypoint sh cvecondor -c 'mkdir -p /data/omp && HOME=/data/omp omp auth import -'
    ```
    and `"responder": { "env": { "HOME": "/data/omp" } }`. The `omp auth export` copy copies every login stored on that machine; tell the user so before they run it.
- **Anything else:** `"responder": { "command": ["<cli>", "<headless flag>", "<auto-approve flag>", "{prompt}"], "env": { "<LOGIN_VAR>": "${<LOGIN_VAR>}" } }`, from steps 1–4. In a container, the image needs that CLI: add it to the `Dockerfile` (as the `AGENTS` build arg does for claude, codex and omp) or build on top of the image.

Prove it in step 7 with one propose-only response.

### 4c. Where they hear about it

**The rule, built into the notifier code:** a notifier gets `urgent` notices only, unless its `events` list more. An urgent notice is one line (cut at 300 characters, no body): what, where, what is being done. Everything else (each cycle's cases, the responder's results, proposals, "fine for now", secrets found) is written under `reports/` and listed in the inbox (`cvecondor inbox`), which the agent in charge reads at the start of every conversation (`AGENTS.md`).

**Urgent goes everywhere they can be reached, never one channel alone.** A single bot or inbox can be muted, down or unread. Find every way this user can be reached from the machine where CVECondor runs, then record each one:

1. **Look first, read-only, then ask for the rest.** Candidates:
   - their agent's own chat or notifications: this agent's harness may have a send or notify command, a messaging bridge, or an inbox the user reads; check your own environment and CLI help;
   - their own machine, when the watcher runs elsewhere: `cvecondor follow` puts each urgent line into an ordinary session of their agent there (4d);
   - desktop notifications on a machine they sit at (`osascript -e 'display notification …'` on a Mac, `notify-send` on Linux), reachable from the watcher only if it runs there or can ssh there;
   - phone push (ntfy, Pushover, their own push service);
   - Slack, Telegram, email, a webhook (below);
   - anything they already get alerts through (an on-call tool, a team chat).
2. **Record each one where it fits:**
   - **A notifier** (`notify`, the types below) for anything CVECondor can post to itself. Its `events` default to `["urgent"]`. Every notifier listening for `urgent` gets every urgent line.
   - **`responder.reach`** for the ways only an agent session can use: shell commands the responder runs itself with the urgent line on stdin (for example the command that drops a message into their agent's chat, or a desktop notification over ssh). The responder runs every one for each urgent line and says in its report which worked. In propose mode the `claude` preset allows exactly these commands; with another agent's propose command, check it can run them (its sandbox or tool list), or they only work in update and act runs.
3. **Test each one** in step 7: `notify-test` sends a line through every notifier; run each `responder.reach` command once with a test line on stdin. Ask the user to confirm each arrived, and drop the ones that don't.

Walk them through each channel they agree to. Each secret goes in the env file through the recipe; the config holds only `${NAME}` references and the non-secret ids. Fields are in the README's config reference.

- **Telegram** (`{ "type": "telegram", "botToken": "${TELEGRAM_BOT_TOKEN}", "chatId": "<id>" }`, plus `"replies": true` to let them answer there; replies need a responder): follow **`docs/telegram.md`**. The user creates a bot of their own in @BotFather, the token goes into the env file through the recipe, `cvecondor telegram-chat` finds the chat id and writes it into the config for you, and `status` and `notify-test telegram` prove it. The user only creates the bot, taps Start and sends a test message. Replies are text only: voice messages get no answer yet ([issue #2](https://github.com/fredluz/cvecondor/issues/2)).
- **Slack** (`{ "type": "slack", "webhookUrl": "${SLACK_WEBHOOK_URL}" }`): at `https://api.slack.com/apps` → **Create New App** → **From scratch** (name `cvecondor`, their workspace) → **Incoming Webhooks** → turn it on → **Add New Webhook to Workspace** → pick the channel → **Allow**. They copy the webhook URL (it is the secret) and run the recipe with `NAME` = `SLACK_WEBHOOK_URL`. A workspace may require an admin to approve the app.
- **Email** (`{ "type": "email", "host", "port", "security", "user", "pass": "${SMTP_PASSWORD}", "from", "to" }`): ask for their provider's SMTP host and port (587 with `starttls`, or 465 with `tls`) and the sending address. Only the password is a secret; it goes in through the recipe with `NAME` = `SMTP_PASSWORD`. With Gmail or Google Workspace that is an app password (Google Account → Security → 2-Step Verification on → **App passwords**), not their account password; Microsoft 365 and Fastmail have the same idea. A transactional sender (Postmark, Resend, SES) gives SMTP credentials too.
- **Webhook** (`{ "type": "webhook", "url": "${WEBHOOK_URL}", "headers": { "Authorization": "Bearer ${WEBHOOK_TOKEN}" } }`): any endpoint that accepts a JSON POST (ntfy, Discord's webhook URL, their own service). The URL, and a token if it needs one, go through the recipe.

- **Where else their agent can be reached, for the rest** (optional): if their agent has a way in (a chat it reads, a bridge with a webhook, a command that drops a message in its inbox), the non-urgent summaries can go there too: a notifier with `"events": ["case", "report", "secrets"]` (plus `"urgent"` if it should also get urgent lines). Never point summaries at their phone channel. If their agent has no way in, the inbox alone is enough: you read it when they open you.

`notify-test` in step 7 sends one line through every notifier (`notify-test telegram`, or a number from `status`, only one); ask them to confirm each arrived.

### 4d. Their own machine: `cvecondor follow` (offer it whenever the watcher runs somewhere else)

A watcher on a server can't reach the agent on the user's laptop, and a phone line can't be talked back to. `cvecondor follow` runs on the machine they sit at: it pulls the watcher's new urgent lines and puts each into an **ordinary interactive session** of their agent, started in this checkout so it loads `AGENTS.md` and is the agent in charge. They then just talk to it: "what is this?", "do it". Ask if they want it; it is the "their agent's own chat" channel of 4c. If the watcher runs on the machine they sit at, they don't need it: the inbox is read when they open you, and a desktop notifier (`command` notifier with `osascript`/`notify-send`) covers the push.

1. **Their agent's interactive command.** Follow starts a new interactive session of their agent for each delivery, so it needs the command that opens one with a first message: `agent` in `follow.json`, an argv with `{prompt}` where the opening message goes. Work it out for the CLI they use (you, usually: step 4b found which), from its own help: the interactive form that takes a prompt as an argument (not the headless `-p`/`exec` form the responder uses), plus anything it needs to start unattended in this folder. `["claude", "{prompt}"]`, `["codex", "{prompt}"]` and `["omp", "{prompt}"]` have shorthands (`"agent": "claude"`); anything else is its own argv, with the binary's full path from `which` if the unit's `PATH` won't reach it. A CLI that can't take a first message as an argument gets a small wrapper script that can. The default needs tmux (from their package manager).
   **Their terminal.** The default works in any terminal: one tmux session whose window holds every session as a pane, opened in a terminal window when none is attached (macOS Terminal, or a Linux terminal found on `PATH`). If they live in another terminal (iTerm, Ghostty, kitty, WezTerm, their agent's own app), fit it to that and tell them which you chose:
   - their terminal, same shared tmux window: `terminal` is that terminal's argv to open a window running `{attach}`;
   - their terminal's own panes or tabs instead of tmux: `deliver` is a command (often a short script) that opens a pane or tab there running their agent in this folder with `{prompt}` as its first message, all in one window;
   - an agent with its own "send a message into my open session" command: `deliver` is that command, with `{line}`.
2. **Which way the watcher is read**, from `deployment.md` (the command prefix without `cvecondor`): `["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "<host>", "docker", "exec", "<container>"]` with `stateDir` `/data` for a container; `["ssh", "<host>"]` and the state dir for a daemon on a server; nothing for a watcher on this machine. Prove `ssh` works without a prompt, and that `<prefix> tail -n 1 <stateDir>/inbox.jsonl` prints (an empty inbox is a "No such file" the first time; that is fine).
3. **Write `~/.config/cvecondor/follow.json`** from `examples/follow.example.jsonc` (no secrets in it). Set `dir` to the folder you are running in now: it is where the user is talking to you, so it is already trusted by the agent, and follow's sessions start there with AGENTS.md loaded. Confirm that with the user in one line rather than asking them to open anything first. Leave `layout` at `panes` unless they want one window per session (`windows`) or one ongoing session that later lines are typed into (`one`).
4. **Install it** as a launchd agent (`deploy/launchd/com.cvecondor.follow.plist`, `launchctl bootstrap gui/$(id -u) …`) or a systemd user unit (`deploy/systemd/cvecondor-follow.service`, `systemctl --user enable --now cvecondor-follow`). Fill in the paths; the unit's `PATH` must reach tmux, the agent and ssh. The first time it opens a Terminal window or a notification, macOS asks to allow it: tell them to say yes.
5. **Send the test line through it, twice:** `cvecondor follow --test`, then again. It goes through the real delivery (and the notification). It worked when: one window shows their agent's session with the test line (a pane of the tmux session, or their own terminal's pane), the agent answers it as the agent in charge, and the second test adds a second session to that same window rather than a new window (with `layout` `one`, it lands in the same session). Ask them to confirm, then close the test sessions. Say that a real urgent line behaves the same, once, even across restarts and a sleeping laptop, and that `tmux -L cvecondor attach` (or the `session`/`tmuxSocket` they set) brings the window back after they close it.

Record in `deployment.md` (step 7.9) that follow runs on that machine, how, and its config path.

### 4e. The classifier.dev key (if they chose their own)

They create the key in their classifier.dev account, then run the env-file recipe with `NAME` = `CLASSIFIER_API_KEY`, and clear the terminal. The config reads it from the env file by itself (`classifier` defaults to `CLASSIFIER_API_KEY`); write `"classifier": { "apiKey": "${CLASSIFIER_API_KEY}" }` only to make that explicit. `cvecondor status` says `Classifier:` with the key's state on its second line. For the anonymous tier, `"classifier": { "anonymous": true }` and nothing in the env file. Without either, say once in the summary that written advisories and vendor news are decided by name matching, so expect more false alarms.

## 5. The rotation map and runbooks

**Rotation map** (`~/.config/cvecondor/rotation-map.json`, or next to the config): for each key name, every place it is stored. Use names and places only:

```json
{ "OPENAI_API_KEY": [{ "place": "vercel:acme-web (production)", "vendor": "vercel" }, { "place": "web1:/opt/api/.env" }, { "place": "github:acme/api (Actions secret)" }] }
```

Build it from what you listed in step 2: platform env names, Actions secret names, compose `.env` files and container env names on servers. `place` is free text: say where, as precisely as you know it (`vercel:acme-web (production)`, `web1:/opt/api/.env`, `unknown host running acme/api`). `vendor`, when the place is a vendor's, is its catalogue id. When a vendor or place is compromised, CVECondor uses the map to say exactly what to rotate where.

**Runbooks** (`~/.config/cvecondor/runbooks/<service>.md`, one per service that matters). Name each file after the service as CVECondor sees it: a container name, a systemd unit, a repo name, or, for a server's own packages, the server's collector name (`web1.md`: OS upgrades, sshd and the reverse proxy). A runbook is attached to a case when its name and the place's name contain one another, so `shop.md` matches container `shop-wordpress-1`, and `api.md` matches repo `acme/api`. Each is four short sections, with commands taken from how the service is really deployed:
- **Stop:** how to take it offline restorably, and how to check that.
- **Bring back:** the exact commands, dependants first.
- **Rotate:** each key it uses, and where to change it.
- **Redeploy:** how a fixed version goes out.

The responder follows these instead of improvising.

## 6. Write the config

Start from `examples/config.example.jsonc`. Keep it short: only what applies. Typically:

- `collectors`:
  - `github`, with the repo list;
  - on a server where CVECondor runs: `host` and `docker`. Give both a `name` (for example the server's name, `"name": "web1"`), which is how messages refer to it. `host` reads the server's own packages and env files. The images its containers run, and what is inside them, come only from `docker`, so a server with containers needs both;
  - for a server elsewhere: `ssh`, with a dedicated key and a user that can only read (see below).
- `priority`, `responder` (`agent`, `actOn`, `updateExcept`, `notes` with anything the responder must know or never touch), `notify`, `vendors`, `rotationMap`, `runbooks`.

**Covering a server** (when they have one): run CVECondor on the server itself. That is the simplest setup, and both read-only collectors work from there.
- **Plain daemon:** `deploy/systemd/cvecondor.service`, as a dedicated `cvecondor` user. The `host` collector reads the package databases as that user. For containers, give it the Docker API through a GET-only socket proxy rather than the docker group, which is root-equivalent.
- **Container:** `deploy/docker-compose.yml`, which mounts the host's `/` read-only and starts that GET-only proxy.

If CVECondor runs elsewhere, use the `ssh` collector with a key used only for it. Prefer a user whose sudo is limited to the read commands the script uses, or no sudo and a GET-only Docker proxy. Whatever account the responder acts with is separate.

`cvecondor.env` (`chmod 600`, next to the config) must hold exactly the variables the config references, each put there with the recipe in step 4; check by name with `cut -d= -f1`. Name the config `config.json` in `~/.config/cvecondor/` (comments are allowed in it), and the commands find both without `--config`. Notifier fields, including the `command` notifier's contract, are in the README's config reference. Then check the config loads: `cvecondor status`. Its second line shows whether the rotation map and runbooks were found.

**In a container,** mount the config dir (config and env file together) read-only at `/config`, from outside the checkout, readable by uid 1000; CVECondor loads `cvecondor.env` from there itself, so never pass it as `env_file` or `environment` (that would put every secret in the container's environment, visible to anyone who can `docker inspect`). The shipped compose file mounts `$CVECONDOR_CONFIG_DIR`. A container that covers GitHub repos only needs neither the host mount nor the socket proxy. The command prefix is then `docker exec <container> cvecondor`; for one-off commands before it is up, `docker compose run --rm <service> <command>`.

## 7. Start it, prove it, report

Run these where it runs, as the user it runs as: the command prefix you will write into `deployment.md` (`ssh <host> docker exec <container> cvecondor`, `ssh <host> sudo -u cvecondor cvecondor`, or `cvecondor` on this machine). Add `--config <file>` (or set `CVECONDOR_CONFIG`) only if the config isn't at `~/.config/cvecondor/config.json` for that user.

1. `cvecondor inventory`: every collector `ok`. Fix any `FAIL` and investigate any warning (a missing gitleaks, a token without access to a repo).
2. `cvecondor vendors`: matches what you and the user agreed.
3. `cvecondor notify-test`: ask the user to confirm the message arrived. If they use `follow` (4d), also `cvecondor follow --test` on their machine.
4. `cvecondor baseline --out <state dir>/baseline.md` (the state dir is printed by `status`; never write it into the repo): **show the user the baseline.** That is what is already vulnerable (critical, high and exploited, per repo or service, each rated for them: act today, act this week, plan it, or not a real risk, with why) and the secrets sitting where they shouldn't. Don't hide it. Exploited ones get the normal response in the first cycle; the rest are assessed and proposed, not acted on.
5. Start it the way you agreed:
   - systemd: `systemctl enable --now cvecondor`;
   - container: `docker compose up -d --build` (with `CVECONDOR_CONFIG_DIR` set);
   - launchd: `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.cvecondor.plist` (a LaunchAgent runs only while that user is logged in);
   - GitHub Action: commit `examples/github-workflow.yml` and the config (it holds `${NAME}` references only) to a private repo of theirs, set `uses:` to this repo at a pinned commit, set the action's `agent` input if the responder is claude or codex, and add the secrets to that repo's Actions secrets. The action builds CVECondor once per source version and caches it;
   - cron, or by hand: `cvecondor cycle` on a schedule. Nothing watches between runs; say so in `deployment.md`.

   Then run one cycle: `cvecondor cycle` (or let the daemon's first cycle run). The first cycle reads every feed for the first time: what they already carry is history, not news. The baseline comes from the inventory instead.
6. `cvecondor status`: the last cycle has no errors, the sources are polled, and every collector is `ok`.
7. **Refresh on lockfile change:** the inventory refreshes hourly, and unchanged repos cost nothing. For a faster reaction in the Action setup, keep the workflow's `push: paths:` trigger.
8. **The responder** (if configured):
   - offer to try it once on a baseline case in propose mode: `cvecondor respond <key> --mode propose`. It changes nothing and shows them what a response looks like. It also proves the CLI is logged in where CVECondor runs;
   - **the act account** (if set up): from where the responder runs, as its user (`docker exec <container> …` or `sudo -u cvecondor …`), through the exact access `responder.notes` names (each command below prefixed with its `ssh … <server>-act`): `sudo -n -l` lists only the allowed commands; `sudo -n true`, an `apt-get install --only-upgrade -o …` and a `systemctl enable <path>` are refused; one harmless real action and its undo, with their OK, e.g. read a container's restart policy (`sudo -n docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' <c>`), set it to the same value (`sudo -n docker update --restart=<same> <c>`), and read it back unchanged; and a dry-run upgrade (`sudo -n apt-get install --only-upgrade -s <pkg>`). Each must succeed without a password prompt. Record the result in `deployment.md`.
9. **Write `~/.config/cvecondor/deployment.md`** on the machine you are talking to them from, plus a copy in the config dir where CVECondor runs if that is elsewhere. It is how you, or the next agent, find the watcher again. Keep it short:
   - **Where it runs:** the machine, and how it runs (systemd, container name, launchd label, or the Action's repo).
   - **Command prefix:** how to run `cvecondor <command>` there, e.g. `ssh <host> docker exec cvecondor cvecondor`, or `cvecondor` itself.
   - **Logins and their expiry:** which tokens are in the env file (names only), when each expires, and where each is revoked.
   - **Paths:** the config, `cvecondor.env`, rotation map, runbooks, state dir and logs.
   - **Restart and update:** the exact commands, including how it is rebuilt from source after a `git pull` (where the checkout is, `cargo build --release --locked` and where the binary goes, or `docker compose build`).
   - **Choices:** the decisions made at setup and why: the token shape, who gets told, what may act, anything they said never to touch.

   Never put a secret value in it.

Then tell the user, briefly:
- where it runs, and that from now on they can just ask you (in this repo) how it is doing, what it found, or to handle something;
- what it covers (repos, servers, vendors);
- the baseline (critical/high per service);
- secrets to move or rotate;
- dead deployments worth shutting down;
- what the responder does on its own: it updates when a fix exists (except in `updateExcept`; pull requests it never merges, you do when they say so), and it works around exploitable problems or stops a service only in `actOn`; on a server, only through the act account if they set it up; everything else it only proposes;
- what isn't covered.
