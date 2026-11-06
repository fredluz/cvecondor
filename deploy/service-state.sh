#!/bin/sh
# Writes the service-state file the watcher's `service-state` collector reads:
# every container's name, compose project and service, image, state word,
# published ports and traefik labels — never environment values.
#
# Run it on the host every few minutes (cron or a systemd timer), as a user
# allowed to `docker inspect`, writing where the watcher mounts it read-only:
#
#   */2 * * * * root /opt/cvecondor/service-state.sh /var/lib/cvecondor/services.json
#
# Needs docker and jq. Exit 0 with no containers is a valid, empty file.
set -eu

OUT="${1:?usage: service-state.sh <output file>}"
command -v docker >/dev/null && command -v jq >/dev/null || {
	echo "service-state: needs docker and jq" >&2
	exit 1
}

TMP=$(mktemp "${OUT}.XXXXXX")
trap 'rm -f "$TMP"' EXIT

IDS=$(docker ps -aq)
if [ -z "$IDS" ]; then
	CONTAINERS='[]'
else
	# shellcheck disable=SC2086
	CONTAINERS=$(docker inspect $IDS | jq '[ .[] | {
		name: (.Name | ltrimstr("/")),
		project: .Config.Labels["com.docker.compose.project"],
		service: .Config.Labels["com.docker.compose.service"],
		image: .Config.Image,
		state: .State.Status,
		ports: [ .HostConfig.PortBindings // {} | to_entries[] | .key as $p
			| (.value[]? | "\(.HostIp):\(.HostPort)->\($p)") ],
		labels: (.Config.Labels // {}) | with_entries(select(.key | startswith("traefik.")))
	} ]')
fi

jq -n --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson containers "$CONTAINERS" \
	'{ generatedAt: $now, containers: $containers }' >"$TMP"
chmod 0644 "$TMP"
mv -f "$TMP" "$OUT"
trap - EXIT
