// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! A remote Linux host over ssh: one read-only POSIX sh script on stdin prints
//! `@@section@@` blocks (os-release, packages, binary versions, project config
//! files and, with docker, every container's inspect JSON plus files copied out
//! with `docker cp … - | tar -xO`, never exec). Every body line is prefixed
//! with `|` so a file or log line can never forge a section marker. Text to be
//! secret-scanned arrives over the pipe and is scanned in memory, never written.

use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use indexmap::IndexMap;
use regex::Regex;

use super::CollectContext;
use super::host::{HOST_BINARIES, basename, runtime_name};
use super::system::{
    Base, ContainerInput, ContainerInspect, LOG_RISK, TextSource, apk_items, container_inventory, dedupe, dedupe_signals, dpkg_query_items, file_signals,
    host_file_risk, os_item, osv_ecosystem, scan_file, scan_secrets, sections, version_of,
};
use crate::config::SshCollector;
use crate::manifests::LOCKFILES;
use crate::secrets::Exposure;
use crate::types::{Collected, InventoryItem, ItemKind, ServiceInfo, VendorSignal};
use crate::util::{self, RunOptions};

/// Largest output read from the remote script.
pub const MAX_OUTPUT: usize = 512 << 20;

/// The `find` name filter for compose and env files, as the remote script embeds it.
pub const FIND_NAMES: &str = r"\( -name 'docker-compose*.y*ml' -o -name 'compose*.y*ml' -o -name '.env*' \)";

/// What the remote script may do.
#[derive(Debug, Clone, Copy)]
pub struct ScriptOptions {
    /// Prefix privileged reads with `sudo -n`.
    pub sudo: bool,
    /// Also list every container: inspect JSON, files copied out, logs.
    pub docker: bool,
}

// The script is assembled from pieces (no `format!`: the shell is full of braces).
const DOCKER_HEAD: &str = r##"
S dockererr; command -v docker >/dev/null 2>&1 && { o=$(D ps -aq --no-trunc 2>&1) || printf '%s\n' "$o" | head -3 | B 2000; }
S containers; D ps -aq --no-trunc 2>/dev/null | while read c; do D inspect --format '{{json .}}' "$c" 2>/dev/null; done | B 50000000
S images; D ps -aq --no-trunc 2>/dev/null | while read c; do D inspect --format '{{.Image}}' "$c" 2>/dev/null; done | sort -u | while read i; do printf '%s\t%s\n' "$i" "$(D image inspect --format '{{json .Config.Env}}' "$i" 2>/dev/null)"; done | B 5000000
for c in $(D ps -aq --no-trunc 2>/dev/null); do
  wd=$(D inspect --format '{{.Config.WorkingDir}}' "$c" 2>/dev/null); wd=${wd%/}
  for f in /etc/os-release /usr/lib/os-release /var/lib/dpkg/status /lib/apk/db/installed "##;

const DOCKER_TAIL: &str = r##"; do
    out=$(D cp -L "$c:$f" - 2>/dev/null | tar -xO 2>/dev/null | head -c 8000000)
    [ -n "$out" ] && { S "cfile $c $f"; printf '%s\n' "$out" | B 8000000; }
  done
  [ "$(D inspect --format '{{.State.Running}}' "$c" 2>/dev/null)" = true ] && { S "logs $c"; D logs --tail 2000 "$c" 2>&1 | B 2000000; }
  DIRS="$DIRS
$(D inspect --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$c" 2>/dev/null)"
done"##;

const SCRIPT_HEAD: &str = r##"set +e
SU='"##;

const SCRIPT_FUNCTIONS: &str = r##"'
S() { printf '\n@@%s@@\n' "$1"; }
B() { head -c "$1" | sed 's/^/|/'; }
D() { $SU docker "$@"; }
DIRS=''
S os; { cat /etc/os-release 2>/dev/null || cat /usr/lib/os-release 2>/dev/null; } | B 100000
S kernel; uname -r | B 1000
S dpkg; dpkg-query -W -f '${Package}\t${Version}\t${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n' 2>/dev/null | B 50000000
S apk; cat /lib/apk/db/installed 2>/dev/null | B 50000000
S hostbin
for p in "##;

const SCRIPT_PROBES_LOOP: &str = r##"; do b=${p%%:*}; a=${p#*:}; x=$(command -v "$b" 2>/dev/null) && printf '%s\t%s\n' "$x" "$("$x" $a 2>&1 | head -1)"; done | B 100000
"##;

const SCRIPT_DIRS: &str = r##"
DIRS="$DIRS
$(for u in /etc/systemd/system/*.service; do $SU sed -n 's/^WorkingDirectory=-\{0,1\}\(\/.*\)$/\1/p' "$u" 2>/dev/null; done)"
for u in /etc/systemd/system/*.service; do $SU sed -n 's/^EnvironmentFile=-\{0,1\}\(\/.*\)$/\1/p' "$u" 2>/dev/null; done | sort -u | while read f; do
  m=$($SU stat -c %a "$f" 2>/dev/null) && { S "envfile $m $f"; $SU cat "$f" 2>/dev/null | B 1000000; }
done
{ printf '%s\n' "$DIRS" | sort -u | while read d; do [ -n "$d" ] && $SU find "$d" -maxdepth 1 -type f "##;

const SCRIPT_FIND_OPT: &str = r##" 2>/dev/null; done
  $SU find /opt /srv /root -mindepth 2 -maxdepth 2 -type f "##;

const SCRIPT_FIND_HOME: &str = r##" 2>/dev/null
  $SU find /home -mindepth 3 -maxdepth 3 -type f "##;

const SCRIPT_TAIL: &str = r##" 2>/dev/null; } | sort -u | while read f; do
  m=$($SU stat -c %a "$f" 2>/dev/null) && { S "file $m $f"; $SU cat "$f" 2>/dev/null | B 1000000; }
done
S end
"##;

/// The read-only script run on the remote host.
pub fn ssh_script(options: ScriptOptions) -> String {
    let probes = HOST_BINARIES.iter().map(|(b, args)| format!("{b}:{}", args.join(" "))).collect::<Vec<_>>().join(" ");
    let lockfiles = LOCKFILES.iter().map(|l| format!("\"$wd/{l}\"")).collect::<Vec<_>>().join(" ");
    let docker = if options.docker { [DOCKER_HEAD, &lockfiles, DOCKER_TAIL].concat() } else { String::new() };
    [
        SCRIPT_HEAD,
        if options.sudo { "sudo -n " } else { "" },
        SCRIPT_FUNCTIONS,
        &probes,
        SCRIPT_PROBES_LOOP,
        &docker,
        SCRIPT_DIRS,
        FIND_NAMES,
        SCRIPT_FIND_OPT,
        FIND_NAMES,
        SCRIPT_FIND_HOME,
        FIND_NAMES,
        SCRIPT_TAIL,
    ]
    .concat()
}

/// What the script's output holds: an inventory, and the texts still to be secret-scanned (by the caller).
#[derive(Debug, Clone, Default)]
pub struct ParsedSsh {
    pub collected: Collected,
    pub sources: Vec<TextSource>,
}

/// The script's output → inventory, plus the texts to secret-scan (scanned by the caller).
pub fn parse_ssh(host: &str, output: &str) -> Result<ParsedSsh> {
    static FILE_SECTION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(file|envfile) ([0-7]+) (/[^\n\r\x{2028}\x{2029}]+)$").expect("valid regex"));
    // Only `|`-prefixed lines are content; the prefix is dropped.
    let parts: Vec<(&str, String)> =
        sections(output).into_iter().map(|p| (p.name, p.lines.iter().filter_map(|l| l.strip_prefix('|')).collect::<Vec<_>>().join("\n"))).collect();
    if !parts.iter().any(|(name, _)| *name == "end") {
        bail!("remote collection was cut short (no end marker)");
    }
    let body = |name: &str| parts.iter().find(|(n, _)| *n == name).map_or("", |(_, b)| b.as_str());
    let base = Base::new(host, "host");
    let os = body("os");
    let eco = osv_ecosystem(os);
    let pkg_base = Base { ecosystem: eco.as_deref(), ..base };
    let mut items: Vec<InventoryItem> = os_item(os, base);
    let kernel = crate::util::js_trim(body("kernel"));
    items.push(base.item(ItemKind::Os, "linux kernel", if kernel.is_empty() { "unknown" } else { kernel }));
    items.extend(dpkg_query_items(body("dpkg"), pkg_base));
    items.extend(apk_items(body("apk"), pkg_base));
    for line in body("hostbin").split('\n') {
        let mut fields = line.split('\t');
        let (path, text) = (fields.next().unwrap_or_default(), fields.next().unwrap_or_default());
        let Some(version) = version_of(text) else { continue };
        if path.is_empty() {
            continue;
        }
        let mut item = base.item(ItemKind::Runtime, runtime_name(basename(path)), version);
        item.path = Some(path.to_string());
        items.push(item);
    }
    let mut services: Vec<ServiceInfo> = Vec::new();
    let mut secrets = Vec::new();
    let mut signals: Vec<VendorSignal> = Vec::new();
    let mut sources: Vec<TextSource> = Vec::new();
    let mut images: IndexMap<&str, Option<Vec<String>>> = IndexMap::new();
    for line in body("images").split('\n') {
        let mut fields = line.split('\t');
        let (id, env) = (fields.next().unwrap_or_default(), fields.next());
        // An image gone mid-run has no env to parse.
        if let (false, Some(env)) = (id.is_empty(), env)
            && let Ok(env) = serde_json::from_str::<Option<Vec<String>>>(env)
        {
            images.insert(id, env);
        }
    }
    for line in body("containers").split('\n') {
        let Ok(c) = serde_json::from_str::<ContainerInspect>(line) else { continue };
        let id = c.id.as_deref().unwrap_or("undefined");
        let prefix = format!("cfile {id} ");
        let files: IndexMap<String, String> =
            parts.iter().filter_map(|(name, body)| name.strip_prefix(prefix.as_str()).map(|path| (path.to_string(), body.clone()))).collect();
        let image_env = images.get(c.image.as_str()).cloned().flatten();
        let result = container_inventory(host, &c, &ContainerInput { image_env, files, probe: None });
        items.extend(result.items);
        services.extend(result.services);
        secrets.extend(result.secrets);
        signals.extend(result.signals);
        let logs = parts.iter().find(|(name, _)| *name == format!("logs {id}"));
        if let Some((_, text)) = logs.filter(|(_, text)| !crate::util::js_trim(text).is_empty()) {
            sources.push(TextSource {
                r#where: format!("container:{}", c.name.strip_prefix('/').unwrap_or(&c.name)),
                location: "logs".to_string(),
                text: text.clone(),
                exposure: Exposure::Log,
                risk: LOG_RISK.to_string(),
                env: None,
            });
        }
    }
    for (name, text) in &parts {
        let Some(m) = FILE_SECTION.captures(name) else { continue };
        let (kind, mode, path) = (&m[1], &m[2], &m[3]);
        if crate::util::js_trim(text).is_empty() || kind == "file" && !scan_file(basename(path)) {
            continue;
        }
        let env = kind == "envfile";
        let world_readable = u64::from_str_radix(mode, 8).is_ok_and(|m| m & 0o004 != 0);
        signals.extend(file_signals(path, text, host, "host", env.then_some(true)));
        sources.push(TextSource {
            r#where: "host".to_string(),
            location: path.to_string(),
            text: text.clone(),
            exposure: Exposure::HostFile,
            risk: host_file_risk(world_readable).to_string(),
            env: env.then_some(true),
        });
    }
    let warnings: Vec<String> = Some(crate::util::js_trim(body("dockererr")))
        .filter(|e| !e.is_empty())
        .map(|e| format!("docker is installed but `docker ps` failed, so no containers were inventoried: {}", e.replace('\n', " ")))
        .into_iter()
        .collect();
    Ok(ParsedSsh { collected: Collected { items: dedupe(items), services, secrets, signals: dedupe_signals(signals), warnings }, sources })
}

/// Runs `ssh` with `input` on its stdin. A run that was cut short still counts when the script got to its end marker.
fn run_ssh(args: &[String], input: &str, timeout: Duration) -> Result<String> {
    let argv: Vec<String> = std::iter::once("ssh".to_string()).chain(args.iter().cloned()).collect();
    let opts = RunOptions { stdin: Some(input.as_bytes().to_vec()), timeout: Some(timeout), max_output: MAX_OUTPUT, ..RunOptions::default() };
    let out = util::run(&argv, &opts)?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    // Over the output cap or past the deadline the TS kills the child: no exit code.
    let killed = out.truncated || out.timed_out;
    if (!killed && out.code == Some(0)) || (!out.truncated && text.contains("\n@@end@@")) {
        return Ok(text);
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let tail: String = stderr.chars().rev().take(2000).collect::<Vec<_>>().into_iter().rev().collect();
    let code = if killed { "null".to_string() } else { out.code.map_or_else(|| "null".to_string(), |c| c.to_string()) };
    Err(anyhow!("ssh exited {code}: {}", crate::util::js_trim(&tail).split('\n').next_back().unwrap_or_default()))
}

/// The `ssh` arguments for a collector: batch mode, a connect timeout, port, key, extra options, host, `sh -s`.
pub fn ssh_args(config: &SshCollector) -> Vec<String> {
    let mut args: Vec<String> = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=15"].map(str::to_string).into();
    if let Some(port) = config.port {
        args.extend(["-p".to_string(), port.to_string()]);
    }
    if let Some(identity) = &config.identity_file {
        args.extend(["-i".to_string(), identity.to_string_lossy().into_owned(), "-o".to_string(), "IdentitiesOnly=yes".to_string()]);
    }
    for option in &config.ssh_options {
        args.extend(["-o".to_string(), option.clone()]);
    }
    args.extend([config.host.clone(), "sh".to_string(), "-s".to_string()]);
    args
}

pub fn collect_ssh(config: &SshCollector, context: &CollectContext) -> Result<Collected> {
    if config.host.starts_with('-') {
        bail!("ssh host must not start with \"-\"");
    }
    let timeout = Duration::try_from_secs_f64(config.timeout_seconds.max(0.0)).unwrap_or(Duration::from_secs(600));
    let output = run_ssh(&ssh_args(config), &ssh_script(ScriptOptions { sudo: config.sudo, docker: config.docker }), timeout)?;
    let ParsedSsh { mut collected, sources } = parse_ssh(&config.name, &output)?;
    (context.log)(&format!("{}: {} items, scanning {} texts for secrets", config.name, collected.items.len(), sources.len()));
    let mut warnings = std::mem::take(&mut collected.warnings);
    let found = scan_secrets(&config.name, &sources, &mut warnings);
    collected.secrets.extend(found);
    collected.warnings = warnings;
    Ok(collected)
}
