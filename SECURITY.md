# Security policy

CVECondor reads your repos and servers, holds tokens, and hands work to an agent that can push branches. A flaw in it matters, so please report one privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: the repository's **Security** tab → **Report a vulnerability** (https://github.com/fredluz/cvecondor/security/advisories/new). Please don't open a public issue, pull request or discussion for it.

Include what you can: the version or commit (`cvecondor --version`, `git rev-parse HEAD`), how it runs (container, systemd, launchd, the GitHub Action), the steps or a proof of concept, and what an attacker gains. Never send a real token or secret; a made-up one shows the same thing.

You get an acknowledgement within 7 days. We agree a disclosure date with you, normally within 90 days, and credit you in the advisory unless you'd rather not be named.

## Supported versions

Fixes go to the default branch. CVECondor is built from source, so updating means pulling the fixed commit and rebuilding.

## In scope

- A secret value (a token, a key, an env value) reaching a log, a notice, a report, the inbox, the responder's environment or any file CVECondor writes.
- A collector writing to what it reads (repos, hosts, containers), or reading beyond what its config grants.
- Feed or advisory text, a Telegram message, or a `follow` line making the watcher, the responder or the user's agent run something it shouldn't (prompt or command injection).
- The responder acting outside its mode or settings (`updateExcept`, `actOn`), merging, force-pushing or deleting.
- Matching flaws that hide a real, critical advisory from a user it applies to.

## Out of scope

- Vulnerabilities in the software CVECondor watches: report those to their maintainers.
- What a user's own agent CLI does with permissions the user gave it outside cvecondor.
