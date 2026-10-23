# Path: exploitable here, no fix yet, opted in → work around it

Follow `common.md` throughout. This path needs mode ACT; in any other mode, follow `propose.md` instead.

1. Send one `urgent` line at once: it is exploitable here and you are working around it now (how it is exploitable, what changes and what could break go in the report).
2. Block the vulnerable path in their own code or config, as narrowly as removes the risk, until the fix ships:
   - turn off the affected feature or option;
   - refuse the input that reaches it (validate, reject, size-limit it in the app or at the reverse proxy);
   - block the path at the proxy or firewall;
   - pin, swap or disable the dependency path (an override to a safe version, an alternative package, removing an unused optional dependency).
   In a repo this is a pull request with a test showing the path is blocked.
3. Verify the service still works and that the path is blocked: test it against the base branch before you offer it (`common.md`, "Every pull request is tested before it is offered"), the new blocking test included.
4. Send one `after` line: what is in place, the test result in plain words, and its undo. The report has how you verified it, and that it stays until the fix ships.
5. Record the workaround with its exact undo in the report, and declare the wait (`common.md`) so the case reopens when the fix ships and the workaround comes out.

If nothing narrower than stopping the service removes the risk, follow `shutdown.md`.
