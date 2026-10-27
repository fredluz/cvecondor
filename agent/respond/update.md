# Path: a fixed release exists → update

Follow `common.md` throughout. No investigation: apply the update.

- **Batch per host and per repo:** every fix this case (and its `related` open cases) needs on one server goes in one maintenance window; every dependency bump in one repo goes in one branch and one pull request.
- **In a repo:** update the dependency (lockfile included), the runtime version files (`.nvmrc`, `engines`, `.tool-versions`) and the base image tag. Test it against the base branch before you offer it (`common.md`, "Every pull request is tested before it is offered"), then push and open the pull request with the result in plain words. You never merge it: each pull request you open goes in the report's `cvecondor-pr` block (`common.md`), and the case waits on the user for the merge.
- **If the update breaks the build or the tests, stop there.** Don't make it pass by changing what the code does or by weakening a check: no security option turned down (allowing short keys, turning off verification), no test assertion relaxed or skipped, no app logic rewritten. Mechanical changes the release notes require (a renamed import, a moved option) are part of the update; anything else is the user's decision. Push the branch, open at most a **draft** pull request whose title says it fails, with the failing output, and say in the report's `## Message` what broke, why, and their choices with your recommendation.
- **On a server:** pull or rebuild on the fixed version and recreate only those services (`docker compose pull <svc>` or `build --pull`, then `up -d --no-deps <svc>`; host packages with `apt-get install --only-upgrade <pkg>`). Keep the old image so a rollback is `docker tag` + `up`. A major-version jump is a patch with risk: back up its data read-only first, or pin the newest fixed release in the same major.
- **Moving to a supported line** (the case says its line gets no fix): the update is the release line it names, a major-version jump with nothing to pin on the old line. In a repo, the branch moves the runtime version files and the base image to that line and is tested like any update, the jump named in the pull request. On a server, rebuild on that line only once the code it runs passes its tests there (the repo's pull request); until then, propose it (`propose.md`) and say what the move takes.
- **Check the service still works:** the running version, its health (HTTP status of its hostname, logs, its tests). The report says what was updated, that it works, and how to roll back. An update sends no message.

Whatever in this case has no fixed release yet goes back through triage's question 4 (exploitable here?) and on to `not-exploitable.md`, `workaround.md` or `propose.md`.

## When the fix the case waited for ships (REOPENED)

Apply it as above and verify it, then **remove the workaround** with the undo recorded in the previous report (named in the case), and bring back anything that was stopped, with one `before` and one `after` line for a service you bring back.
