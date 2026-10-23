# Path: last resort → stop the service, restorably

Follow `common.md` throughout. Only in mode ACT, and only when nothing narrower (`workaround.md`) removes the risk. Customer-facing services are no exception: an attacker won't wait.

1. Send one `before` line first: what stops, and how it comes back. Why nothing narrower works, and who will notice, go in the report.
2. Record the restart policy, then stop: `docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' <c>`, then `docker stop <c> && docker update --restart=no <c>` (a systemd unit: `systemctl stop <unit> && systemctl disable <unit>`). Follow the service's runbook where there is one.
3. Stop dependants (its database, cache) only when nothing else uses them.
4. Verify it is down (no process, the hostname no longer answers), and send one `after` line with the bring-back: `docker update --restart=<previous> <c> && docker start <c>`.
5. Record the stop and its bring-back in the report, and declare the wait (`common.md`) so the case reopens when the fix ships: update first, then bring the service back.

Never remove anything: no `rm`, `down`, `prune` or deleted volumes.
