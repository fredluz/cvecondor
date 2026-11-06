// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! Whether a repo's service is deployed and running — read before triage judges
//! exploitability, so a service that is down is never called exploitable.
//!
//! The watcher container has no Docker socket by design. The state comes from a
//! file a job on the host writes every few minutes and the watcher mounts
//! read-only: `deploy/service-state.sh` is the shipped example. The file is:
//!
//! ```json
//! {
//!   "generatedAt": "2026-11-06T10:00:00Z",
//!   "containers": [
//!     { "name": "blog-app-1", "project": "blog", "service": "app",
//!       "image": "blog:latest", "state": "running",
//!       "ports": ["80/tcp"], "labels": {"traefik.http.routers.blog.rule": "Host(`blog.example.com`)"} }
//!   ]
//! }
//! ```
//!
//! Names, states, published ports and labels only — never environment values.
//! A missing, unreadable or stale file (older than the collector's `maxAge`,
//! default a few write intervals) counts as unknown, and unknown is treated as
//! running: only positive evidence of a down or undeployed service changes a
//! case. The `services` config list names what the file cannot see (a repo's
//! service on another platform: `deployed`/`running` set by hand, or `project`
//! to bind a repo to a compose project whose name differs from the repo's).

use std::path::Path;
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::Result;
use indexmap::IndexMap;
use jiff::Timestamp;
use regex::Regex;
use serde::Deserialize;

use crate::config::{CollectorConfig, Config, ServiceConfig, ServiceStateCollector};
use crate::inventory::CollectContext;
use crate::inventory::system::image_name;
use crate::types::{Collected, Inventory, InventoryItem, ItemKind, ServiceInfo};
use crate::util::{self, parse_time};

/// A compiled-once regex from a literal (as in `inventory/system.rs`).
macro_rules! re {
    ($pattern:expr) => {{
        static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new($pattern).expect("valid regex"));
        &*RE
    }};
}

/// What the watcher knows about a repo's service. `None`: unknown — treated as running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceState {
    /// Deployed, nothing running (containers stopped, created, exited).
    Down,
    /// Nothing deployed at all (a config `deployed: false`, or a `project` the fresh file has no container for).
    Undeployed,
    Running,
}

impl ServiceState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Down => "down",
            Self::Undeployed => "undeployed",
            Self::Running => "running",
        }
    }

    /// `down` and `undeployed` both mean: not exploitable, the case waits on the service.
    pub fn is_down(self) -> bool {
        matches!(self, Self::Down | Self::Undeployed)
    }
}

/// A service's state resolved for a repo, with what to show the responder and the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// `None`: unknown (no collector, a stale file, an unmapped repo) — treated as running.
    pub state: Option<ServiceState>,
    /// One line for the case file and `status` ("the service to come back", a config note).
    pub detail: String,
    /// The containers the state came from, one line each (`name (service): state`).
    pub containers: Vec<String>,
}

/// What a `service-state` file is, once read. Anything but `Fresh` is "unknown" to callers.
#[derive(Debug)]
pub enum FileRead {
    /// Fresh containers, possibly an empty list (the host has none).
    Fresh(Vec<ContainerState>),
    Missing,
    Unreadable(String),
    /// Present but older than the collector's `max_age`: its picture is too old to trust.
    Stale,
    /// Present, unreadable JSON or the wrong shape.
    Bad(String),
}

/// One container in a `service-state` file. Everything optional but `name`: a writer that
/// knows less may still be useful.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ContainerState {
    pub name: String,
    /// Compose project name (`com.docker.compose.project`).
    pub project: Option<String>,
    /// Compose service name (`com.docker.compose.service`).
    pub service: Option<String>,
    pub image: Option<String>,
    /// The Docker state word: `running`, `created`, `exited`, `paused`, …
    pub state: Option<String>,
    /// Published port strings as the writer reports them (`"0.0.0.0:8080->80/tcp"`, `"8080/tcp"`).
    pub ports: Vec<String>,
    /// Labels only — a writer never includes environment values.
    pub labels: IndexMap<String, String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct StateFile {
    generated_at: Option<String>,
    containers: Vec<ContainerState>,
}

/// `true` when the docker state word says the container serves requests.
fn is_running(state: &str) -> bool {
    state.eq_ignore_ascii_case("running")
}

/// The project's key for a `ServiceInfo`: the compose project's name (a `service-state`
/// file's `project`, or `com.docker.compose.project` in an entry another collector
/// recorded), or the compose working directory's basename for docker-collected entries
/// that record a path instead.
fn project_key(service: &ServiceInfo) -> Option<String> {
    let name = service
        .compose
        .as_deref()
        .map(|p| p.trim_end_matches('/').rsplit('/').next().unwrap_or(p))
        .filter(|p| !p.is_empty())?;
    Some(name.to_string())
}

/// Reads and freshness-checks one `service-state` file. `generatedAt` inside the file
/// decides; a file without one falls back to its modification time.
pub fn read_state_file(file: &Path, max_age: Duration, now: Timestamp) -> FileRead {
    let Ok(text) = std::fs::read_to_string(file) else {
        return match std::fs::metadata(file) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => FileRead::Missing,
            Err(e) => FileRead::Unreadable(e.to_string()),
            Ok(_) => FileRead::Unreadable(format!("{}: could not read", file.display())),
        };
    };
    let Ok(parsed) = serde_json::from_str::<StateFile>(&text) else {
        return FileRead::Bad(format!("{}: not a service-state file", file.display()));
    };
    let generated = parsed.generated_at.as_deref().and_then(parse_time).or_else(|| {
        std::fs::metadata(file).ok().and_then(|m| m.modified().ok()).and_then(|mtime| {
            let millis = mtime.duration_since(std::time::UNIX_EPOCH).map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
            Timestamp::from_millisecond(millis).ok()
        })
    });
    match generated {
        Some(t) if now.as_millisecond() - t.as_millisecond() > i64::try_from(max_age.as_millis()).unwrap_or(i64::MAX) => FileRead::Stale,
        Some(_) => FileRead::Fresh(parsed.containers),
        None => FileRead::Stale,
    }
}

/// The services and image items one fresh file contributes to the inventory. A file that is
/// missing, stale or bad contributes nothing — and a warning instead of an error, so the
/// collector's previous services are dropped (a stale file is "unknown", not "keep the last").
pub fn collect_state(config: &ServiceStateCollector, context: &CollectContext) -> Result<Collected> {
    let mut out = Collected::default();
    let containers = match read_state_file(&config.file, config.max_age(), util::now()) {
        FileRead::Fresh(containers) => containers,
        read => {
            out.warnings.push(match read {
                FileRead::Fresh(_) => unreachable!(),
                FileRead::Missing => format!("{}: state file missing; services treated as unknown (running)", config.file.display()),
                FileRead::Stale => format!(
                    "{}: state file older than {}s; services treated as unknown (running)",
                    config.file.display(),
                    config.max_age().as_secs()
                ),
                FileRead::Unreadable(e) => format!("state file unreadable: {e}; services treated as unknown (running)"),
                FileRead::Bad(e) => format!("{e}; services treated as unknown (running)"),
            });
            return Ok(out);
        }
    };
    let host = config.name.as_str();
    for c in containers {
        let running = c.state.as_deref().is_some_and(is_running);
        let mut exposed: Vec<String> = c
            .labels
            .iter()
            .filter(|(key, _)| key.starts_with("traefik.http.routers.") && key.ends_with(".rule"))
            .flat_map(|(_, rule)| re!(r"Host(?:Regexp)?\(`([^`]+)`").captures_iter(rule).map(|m| m[1].to_string()).collect::<Vec<_>>())
            .collect();
        let loopback = re!(r"^(127\.|::1$|\[::1\]|::ffff:127\.|\[::ffff:127\.|localhost)");
        for port in &c.ports {
            if let Some(m) = re!(r"^(?:\[?([0-9a-fA-F.:]+)\]?:)?(\d+)->").captures(port)
                && !loopback.is_match(m.get(1).map_or("0.0.0.0", |g| g.as_str()))
            {
                exposed.push(port.clone());
            }
        }
        exposed.sort();
        exposed.dedup();
        out.services.push(ServiceInfo {
            host: host.to_string(),
            r#where: format!("container:{}", c.name),
            image: c.image.clone(),
            state: c.state.clone().unwrap_or_else(|| "unknown".to_string()),
            restart: None,
            exposed,
            compose: c.project.clone(),
            collector: None,
        });
        if let Some(image) = c.image.as_deref().filter(|i| !i.is_empty()) {
            let (name, tag) = image_name(image);
            out.items.push(InventoryItem {
                host: host.to_string(),
                r#where: format!("container:{}", c.name),
                kind: ItemKind::Image,
                ecosystem: None,
                name,
                version: tag,
                path: Some(image.to_string()),
                running: Some(running),
                dev: None,
                collector: None,
            });
        }
    }
    (context.log)(&format!("{host}: {} containers from {}", out.services.len(), config.file.display()));
    Ok(out)
}

/// The `services` config entry for one repo (`owner/name`, exact match).
fn service_entry<'a>(config: &'a Config, repo: &str) -> Option<&'a ServiceConfig> {
    config.services.iter().find(|s| s.repo.eq_ignore_ascii_case(repo))
}

/// The containers the state files give a project, across every `service-state`
/// collector: the first fresh file that lists the project wins.
fn project_containers(config: &Config, project: &str, now: Timestamp) -> Option<Vec<ContainerState>> {
    for c in &config.collectors {
        let CollectorConfig::ServiceState(collector) = c else { continue };
        if let FileRead::Fresh(containers) = read_state_file(&collector.file, collector.max_age(), now) {
            let mine: Vec<ContainerState> = containers.into_iter().filter(|c| c.project.as_deref() == Some(project)).collect();
            if !mine.is_empty() {
                return Some(mine);
            }
        }
    }
    None
}

/// Whether any `service-state` collector read a fresh file this check.
fn any_fresh_file(config: &Config, now: Timestamp) -> bool {
    config.collectors.iter().any(|c| match c {
        CollectorConfig::ServiceState(collector) => matches!(read_state_file(&collector.file, collector.max_age(), now), FileRead::Fresh(_)),
        _ => false,
    })
}

/// The containers docker/ssh collectors already saw for a project (their `ServiceInfo`s).
fn inventory_containers<'a>(inventory: &'a Inventory, project: &str) -> Vec<&'a ServiceInfo> {
    inventory.services.iter().filter(|s| project_key(s).as_deref() == Some(project)).collect()
}

/// Whether a repo's service is deployed and running. `repo` is `owner/name`; the compose
/// project defaults to the repo's own name (`services[].project` overrides).
///
/// Resolution, in order:
/// 1. Explicit flags: `deployed: false` or `running: false` mark it down (the file can only
///    override an explicit "it runs", never an explicit "it is down").
/// 2. A fresh state file that lists the project: running when any of its containers runs;
///    then containers another collector recorded for the project, the same way.
/// 3. `undeployed` only when the repo is explicitly mapped (`project` or a flag) and some
///    state file is fresh; everything else is unknown — treated as running.
pub fn service_state_for(config: &Config, inventory: &Inventory, repo: &str, now: Timestamp) -> Resolution {
    let entry = service_entry(config, repo);
    let project = entry.and_then(|e| e.project.clone()).or_else(|| repo.rsplit('/').next().map(str::to_string));
    let explicit = entry.is_some_and(|e| e.project.is_some() || e.deployed.is_some() || e.running.is_some());
    let note = entry.and_then(|e| e.note.clone()).unwrap_or_default();

    if let Some(e) = entry {
        if e.running == Some(false) || e.deployed == Some(false) {
            let state = if e.deployed == Some(false) { ServiceState::Undeployed } else { ServiceState::Down };
            return Resolution {
                state: Some(state),
                detail: if note.is_empty() { format!("{} (set in the config)", state.as_str()) } else { format!("{}: {note}", state.as_str()) },
                containers: Vec::new(),
            };
        }
        if e.running == Some(true) || e.deployed == Some(true) {
            // An explicit "it runs" is overridden only by a fresh file that shows it does not.
            if let Some(containers) = project.as_deref().and_then(|p| project_containers(config, p, now))
                && !containers.iter().any(|c| c.state.as_deref().is_some_and(is_running))
            {
                return Resolution {
                    state: Some(ServiceState::Down),
                    detail: "every container stopped (its service-state file shows it)".to_string(),
                    containers: containers.iter().map(describe_container).collect(),
                };
            }
            return Resolution {
                state: Some(ServiceState::Running),
                detail: if note.is_empty() { "running (set in the config)".to_string() } else { note },
                containers: Vec::new(),
            };
        }
    }

    if let Some(p) = project.as_deref() {
        if let Some(containers) = project_containers(config, p, now) {
            let running = containers.iter().any(|c| c.state.as_deref().is_some_and(is_running));
            return Resolution {
                state: Some(if running { ServiceState::Running } else { ServiceState::Down }),
                detail: if running {
                    format!("running ({})", containers.iter().map(|c| c.name.clone()).collect::<Vec<_>>().join(", "))
                } else {
                    "every container stopped".to_string()
                },
                containers: containers.iter().map(describe_container).collect(),
            };
        }
        // Another collector's view of the project (docker/ssh): same words.
        let seen = inventory_containers(inventory, p);
        if !seen.is_empty() {
            let running = seen.iter().any(|s| is_running(&s.state));
            return Resolution {
                state: Some(if running { ServiceState::Running } else { ServiceState::Down }),
                detail: if running {
                    format!("running ({})", seen.iter().map(|s| s.r#where.clone()).collect::<Vec<_>>().join(", "))
                } else {
                    "every container stopped".to_string()
                },
                containers: seen.iter().map(|s| format!("{}: {}", place_of(s), s.state)).collect(),
            };
        }
        if explicit && any_fresh_file(config, now) {
            return Resolution {
                state: Some(ServiceState::Undeployed),
                detail: format!("the state file has no container for project '{p}'"),
                containers: Vec::new(),
            };
        }
    }
    Resolution { state: None, detail: String::new(), containers: Vec::new() }
}

/// The state of every repo the inventory knows: `owner/name` → resolution.
pub fn service_states(config: &Config, inventory: &Inventory, now: Timestamp) -> IndexMap<String, Resolution> {
    let mut repos: indexmap::IndexSet<String> = indexmap::IndexSet::new();
    for item in &inventory.items {
        if let Some(repo) = item.r#where.strip_prefix("repo:") {
            repos.insert(repo.to_string());
        }
    }
    repos.into_iter().map(|repo| (repo.clone(), service_state_for(config, inventory, &repo, now))).collect()
}

fn place_of(s: &ServiceInfo) -> String {
    s.r#where.strip_prefix("container:").unwrap_or(&s.r#where).to_string()
}

fn describe_container(c: &ContainerState) -> String {
    let mut out = c.name.clone();
    if let Some(service) = c.service.as_deref().filter(|s| !s.is_empty() && *s != c.name.as_str()) {
        out = format!("{out} (service {service})");
    }
    format!("{out}: {}", c.state.as_deref().unwrap_or("unknown"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_file(dir: &Path, name: &str, content: &str) -> std::path::PathBuf {
        let file = dir.join(name);
        let mut f = std::fs::File::create(&file).expect("creates the file");
        f.write_all(content.as_bytes()).expect("writes");
        file
    }

    #[test]
    fn a_fresh_file_parses_and_a_stale_one_counts_as_unknown() {
        let dir = std::env::temp_dir().join(format!("cvecondor-service-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let now = "2026-11-06T10:00:00Z".parse::<Timestamp>().expect("a time");
        let fresh = write_file(
            &dir,
            "fresh.json",
            r#"{"generatedAt": "2026-11-06T09:58:00Z", "containers": [{"name": "blog-app-1", "project": "blog", "state": "exited"}]}"#,
        );
        match read_state_file(&fresh, Duration::from_secs(600), now) {
            FileRead::Fresh(c) => {
                assert_eq!(c.len(), 1);
                assert_eq!(c[0].project.as_deref(), Some("blog"));
            }
            other => panic!("fresh file: {other:?}"),
        }
        let stale = write_file(
            &dir,
            "stale.json",
            r#"{"generatedAt": "2026-11-06T08:00:00Z", "containers": [{"name": "blog-app-1", "project": "blog", "state": "exited"}]}"#,
        );
        assert!(matches!(read_state_file(&stale, Duration::from_secs(600), now), FileRead::Stale));
        assert!(matches!(read_state_file(&dir.join("none.json"), Duration::from_secs(600), now), FileRead::Missing));
        let bad = write_file(&dir, "bad.json", "not json");
        assert!(matches!(read_state_file(&bad, Duration::from_secs(600), now), FileRead::Bad(_)));
        // A file with no generatedAt falls back to mtime: written now, fresh.
        let mtime_only = write_file(&dir, "mtime.json", r#"{"containers": [{"name": "a"}]}"#);
        assert!(matches!(read_state_file(&mtime_only, Duration::from_secs(600), Timestamp::now()), FileRead::Fresh(_)));
        std::fs::remove_dir_all(&dir).ok();
    }
}
