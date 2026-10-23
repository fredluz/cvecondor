# Path: propose only

Follow `common.md` throughout. The user hasn't opted these places in for this kind of change (mode PROPOSE, or mode UPDATE with no fix released), so **change nothing outside your working directory**: no branch, no push, no pull request, no change on a server.

1. Finish the facts triage needs for the plan: the call site or config to change, the exact version to move to.
2. Write the plan you would have run, as exact steps: commands, diffs, verification, undo, and what it waits for. Use the path file that would apply with permission (`update.md`, `workaround.md`, `shutdown.md`) as the checklist.
3. The report's `## Message` says: exploitable or not, the rating, and exactly what they need to run, or that adding the service to `actOn` (or `updateWhenFixed`) lets the responder do it next time. If it is exploitable here now, also send one `urgent` line: what is exposed and that they must act (the plan is in the report).
4. Declare the wait if nothing is released yet (`common.md`).
