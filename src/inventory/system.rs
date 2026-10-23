// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! Parsers shared by the host, docker and ssh collectors: os-release, dpkg and
//! apk databases, `--version` output, `@@section@@` script output, tar archives,
//! Docker's multiplexed streams, and one container → inventory mapping. Every
//! collector reads the same raw files, so the same functions turn them into
//! items, services and secret findings whichever way the bytes arrived.

use std::collections::HashSet;
use std::sync::LazyLock;

use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::manifests::{image_runtimes, parse_lockfile};
use crate::secrets::{Exposure, GitleaksMissing, SecretFinding, env_secrets, is_env_file, providers_of, scan_text};
use crate::types::{Collected, InventoryItem, ItemKind, ServiceInfo, VendorSignal, VendorSignalKind};
use crate::util::{js_regex, js_trim};

/// A compiled-once regex from a literal.
macro_rules! re {
    ($pattern:expr) => {{
        static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new($pattern).expect("valid regex"));
        &*RE
    }};
}

/// Like `re!`, with `\s` and `\S` read as the JS classes (they include the BOM, which Node keeps in a file's first line).
macro_rules! jsre {
    ($pattern:expr) => {{
        static RE: LazyLock<Regex> = LazyLock::new(|| js_regex($pattern));
        &*RE
    }};
}

/// `node --version` style outputs → bare version.
pub fn version_of(text: &str) -> Option<&str> {
    re!(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][0-9A-Za-z.]+)?").find(text).map(|m| m.as_str())
}

/// The value of `KEY=value` (optionally quoted) in an os-release text; empty when absent.
fn os_field(os_release: &str, key: &str) -> String {
    // One pattern for every line, first line with this key wins: the same as a per-key `^KEY=…$` regex.
    // `\r?$`: JS `$` also matches before the `\r` of a CRLF file, so a quoted value there still ends at its closing quote.
    re!(r#"(?m)^([A-Za-z0-9_]+)=["']?([^"'\n]*)["']?\r?$"#).captures_iter(os_release).find(|c| &c[1] == key).map_or_else(String::new, |c| c[2].to_string())
}

/// os-release → OSV ecosystem (`Ubuntu:24.04:LTS`, `Debian:12`, `Alpine:v3.22`); `None` for distros OSV has no package data for here.
pub fn osv_ecosystem(os_release: &str) -> Option<String> {
    let id = os_field(os_release, "ID");
    let version = os_field(os_release, "VERSION_ID");
    if version.is_empty() {
        return None;
    }
    match id.as_str() {
        "ubuntu" => Some(format!("Ubuntu:{version}{}", if os_field(os_release, "VERSION").contains("LTS") { ":LTS" } else { "" })),
        "debian" => Some(format!("Debian:{}", version.split('.').next().unwrap_or_default())),
        "alpine" => Some(format!("Alpine:v{}", version.split('.').take(2).collect::<Vec<_>>().join("."))),
        _ => None,
    }
}

pub fn os_name(os_release: &str) -> String {
    let pretty = os_field(os_release, "PRETTY_NAME");
    if !pretty.is_empty() {
        return pretty;
    }
    let name = os_field(os_release, "NAME");
    if name.is_empty() { "unknown OS".to_string() } else { name }
}

/// What an item is attributed to. `ecosystem` is set for OS packages, `running` for a container's items.
#[derive(Debug, Clone, Copy, Default)]
pub struct Base<'a> {
    pub host: &'a str,
    pub r#where: &'a str,
    pub ecosystem: Option<&'a str>,
    pub running: Option<bool>,
}

impl<'a> Base<'a> {
    pub fn new(host: &'a str, r#where: &'a str) -> Self {
        Self { host, r#where, ecosystem: None, running: None }
    }

    /// An item of this place, without ecosystem or path.
    pub fn item(&self, kind: ItemKind, name: impl Into<String>, version: impl Into<String>) -> InventoryItem {
        InventoryItem {
            host: self.host.to_string(),
            r#where: self.r#where.to_string(),
            kind,
            ecosystem: None,
            name: name.into(),
            version: version.into(),
            path: None,
            running: self.running,
            dev: None,
            collector: None,
        }
    }
}

/// The OS item itself, or nothing when there is no os-release.
pub fn os_item(os_release: &str, base: Base) -> Vec<InventoryItem> {
    if js_trim(os_release).is_empty() {
        return Vec::new();
    }
    let version = os_field(os_release, "VERSION_ID");
    vec![base.item(ItemKind::Os, os_name(os_release), if version.is_empty() { "unknown".to_string() } else { version })]
}

fn non_empty(s: Option<&str>) -> Option<&str> {
    s.filter(|s| !s.is_empty())
}

// OSV's Debian and Ubuntu records name source packages, so a binary package is
// listed under its source name and version; `path` keeps the binary name.
fn os_package(
    base: Base,
    binary: &str,
    version: &str,
    source: Option<&str>,
    source_version: Option<&str>,
    seen: &mut HashSet<String>,
    out: &mut Vec<InventoryItem>,
) {
    let name = non_empty(source).unwrap_or(binary);
    let v = non_empty(source_version).unwrap_or(version);
    if !seen.insert(format!("{name}\0{v}")) {
        return;
    }
    let mut item = base.item(ItemKind::OsPackage, name, v);
    item.ecosystem = non_empty(base.ecosystem).map(str::to_string);
    item.path = Some(binary.to_string());
    out.push(item);
}

/// The text after `key:` on the first line of `block` that has something there (a `^key:(.+)$` match with JS's `.`).
fn line_field<'a>(block: &'a str, key: &str) -> Option<&'a str> {
    block.split('\n').find_map(|line| {
        let rest = line.strip_prefix(key)?.strip_prefix(':')?;
        let value = rest.split(['\r', '\u{2028}', '\u{2029}']).next().unwrap_or_default();
        (!value.is_empty()).then_some(value)
    })
}

/// `/var/lib/dpkg/status`: installed packages only, under their source package names.
pub fn dpkg_status_items(text: &str, base: Base) -> Vec<InventoryItem> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for block in re!(r"\n\s*\n").split(text) {
        let field = |key: &str| line_field(block, key).map(js_trim);
        let (Some(pkg), Some(version), Some(status)) = (field("Package"), field("Version"), field("Status")) else { continue };
        if pkg.is_empty() || version.is_empty() || !status.ends_with(" installed") || !status.starts_with("install ") {
            continue;
        }
        let source = field("Source").and_then(|s| re!(r"^(\S+)(?:\s+\(([^)]+)\))?$").captures(s));
        os_package(
            base,
            pkg,
            version,
            source.as_ref().map(|c| c.get(1).map_or("", |m| m.as_str())),
            source.as_ref().and_then(|c| c.get(2)).map(|m| m.as_str()),
            &mut seen,
            &mut out,
        );
    }
    out
}

/// `dpkg-query -W -f '${Package}\t${Version}\t${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n'`.
pub fn dpkg_query_items(text: &str, base: Base) -> Vec<InventoryItem> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for line in text.split('\n') {
        let mut parts = line.split('\t');
        let (pkg, version, source, source_version, status) = (parts.next(), parts.next(), parts.next(), parts.next(), parts.next());
        let (Some(pkg), Some(version)) = (non_empty(pkg), non_empty(version)) else { continue };
        if non_empty(status).is_some_and(|s| !s.starts_with("ii")) {
            continue;
        }
        os_package(base, pkg, version, source, source_version, &mut seen, &mut out);
    }
    out
}

/// `/lib/apk/db/installed`: `P:` name, `V:` version, `o:` origin (the source package OSV names).
pub fn apk_items(text: &str, base: Base) -> Vec<InventoryItem> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    // The TS splits on `\n\s*\n|\n(?=P:)`: first on blank lines, then before each `P:` line.
    for chunk in re!(r"\n\s*\n").split(text) {
        let mut rest = chunk;
        let mut blocks = Vec::new();
        while let Some(at) = rest.find("\nP:") {
            blocks.push(&rest[..at]);
            rest = &rest[at + 1..];
        }
        blocks.push(rest);
        for block in blocks {
            if let (Some(name), Some(version)) = (line_field(block, "P"), line_field(block, "V")) {
                os_package(base, name, version, line_field(block, "o"), None, &mut seen, &mut out);
            }
        }
    }
    out
}

/// One `@@name@@` block of a script's output.
#[derive(Debug, Clone)]
pub struct Section<'a> {
    pub name: &'a str,
    pub lines: Vec<&'a str>,
}

impl Section<'_> {
    pub fn body(&self) -> String {
        self.lines.join("\n")
    }
}

/// `@@name@@` sections of a script's output.
pub fn sections(text: &str) -> Vec<Section<'_>> {
    let marker = re!(r"^@@([^@][^\n\r\x{2028}\x{2029}]*?)@@$");
    let mut out: Vec<Section> = Vec::new();
    let mut current: Option<Section> = None;
    for line in text.split('\n') {
        if let Some(m) = marker.captures(line) {
            out.extend(current.take());
            current = Some(Section { name: m.get(1).map_or("", |g| g.as_str()), lines: Vec::new() });
        } else if let Some(section) = current.as_mut() {
            section.lines.push(line);
        }
    }
    out.extend(current);
    out
}

/// Container env kept as data; everything else is either dropped or, if secret-looking, a name + fingerprint.
pub static ENV_KEEP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(VIRTUAL_HOST|LETSENCRYPT_HOST|VIRTUAL_PORT|[A-Z][A-Z0-9_]*_VERSION)=").expect("valid regex"));

pub fn kept_env<S: AsRef<str>>(env: Option<&[S]>) -> Vec<&str> {
    env.unwrap_or_default().iter().map(AsRef::as_ref).filter(|e| ENV_KEEP.is_match(e)).collect()
}

/// Versions an image declares in its env: the official language images set `NODE_VERSION`, `PHP_VERSION`, …, and
/// `nginx` (and the images bundling it, such as nginx-proxy) sets `NGINX_VERSION`.
pub fn env_runtimes<'a>(env: impl IntoIterator<Item = &'a str>, base: Base) -> Vec<InventoryItem> {
    let mut out = Vec::new();
    for e in env {
        let Some(m) = re!(r"^(NODE|PHP|PYTHON|BUN|RUBY|GOLANG|NGINX)_VERSION=([^\n\r\x{2028}\x{2029}]+)$").captures(e) else { continue };
        let Some(version) = version_of(&m[2]) else { continue };
        let name = if &m[1] == "GOLANG" { "go".to_string() } else { m[1].to_lowercase() };
        let mut item = base.item(ItemKind::Runtime, name, version);
        item.path = Some(format!("env:{}_VERSION", &m[1]));
        out.push(item);
    }
    out
}

/// Python virtualenvs a server's project dirs hold: `<root>/lib/python3*/site-packages/<name>-<version>.dist-info`
/// directory paths → PyPI packages, each with its venv root as `path`. Read from the directory names only.
pub fn dist_info_items<'a>(paths: impl IntoIterator<Item = &'a str>, base: Base) -> Vec<InventoryItem> {
    let mut out = Vec::new();
    for path in paths {
        let path = js_trim(path).trim_end_matches('/');
        let Some((root, rest)) = path.split_once("/lib/python") else { continue };
        let Some(stem) = rest.rsplit('/').next().and_then(|d| d.strip_suffix(".dist-info")) else { continue };
        if !rest.contains("/site-packages/") {
            continue;
        }
        let Some((name, version)) = stem.rsplit_once('-') else { continue };
        if name.is_empty() || !version.starts_with(|c: char| c.is_ascii_digit()) {
            continue;
        }
        let mut item = base.item(ItemKind::Package, name, version);
        item.ecosystem = Some("PyPI".to_string());
        item.path = Some(root.to_string());
        out.push(item);
    }
    out
}

/// Lines `<name> <--version output>` (and pip freeze) from an exec probe.
pub fn probe_items(text: &str, base: Base) -> Vec<InventoryItem> {
    let mut out = Vec::new();
    for line in text.split('\n') {
        let line = js_trim(line);
        if let Some(m) = re!(r"^(node|bun|php|python3|python|deno)\s+([^\n\r\x{2028}\x{2029}]*)$").captures(line)
            && let Some(version) = version_of(&m[2])
        {
            out.push(base.item(ItemKind::Runtime, if &m[1] == "python3" { "python" } else { &m[1] }, version));
        }
        if let Some(pip) = re!(r"^([A-Za-z0-9._-]+)==(\S+)$").captures(line) {
            let mut item = base.item(ItemKind::Package, &pip[1], &pip[2]);
            item.ecosystem = Some("PyPI".to_string());
            item.path = Some("pip list".to_string());
            out.push(item);
        }
    }
    out
}

/// The exec probe run inside a running container when the config allows exec.
pub const EXEC_PROBE: &str = "for x in node bun php python3 deno; do command -v $x >/dev/null 2>&1 && echo \"$x $($x --version 2>&1 | head -1)\"; done; command -v python3 >/dev/null 2>&1 && timeout 20 python3 -m pip list --format=freeze --disable-pip-version-check 2>/dev/null; true";

pub fn dedupe(items: Vec<InventoryItem>) -> Vec<InventoryItem> {
    let mut seen = HashSet::new();
    items
        .into_iter()
        .filter(|item| {
            let key = [
                item.r#where.as_str(),
                item.kind.as_str(),
                item.ecosystem.as_deref().unwrap_or(""),
                item.name.as_str(),
                item.version.as_str(),
                item.path.as_deref().unwrap_or(""),
            ]
            .join("\0");
            seen.insert(key)
        })
        .collect()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerState {
    #[serde(default)]
    pub status: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerConfig {
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub env: Option<Vec<String>>,
    #[serde(default)]
    pub labels: Option<IndexMap<String, String>>,
    #[serde(default)]
    pub working_dir: Option<String>,
    #[serde(default)]
    pub tty: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RestartPolicy {
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HostConfig {
    #[serde(default)]
    pub restart_policy: Option<RestartPolicy>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PortBinding {
    #[serde(default)]
    pub host_ip: String,
    #[serde(default)]
    pub host_port: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkSettings {
    /// `"8080/tcp"` → its host bindings (`null` when the port is only exposed).
    #[serde(default)]
    pub ports: Option<IndexMap<String, Option<Vec<PortBinding>>>>,
}

/// What `docker inspect` returns, as far as the inventory needs it (Docker's own PascalCase names).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerInspect {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub state: ContainerState,
    #[serde(default)]
    pub config: ContainerConfig,
    #[serde(default)]
    pub host_config: Option<HostConfig>,
    #[serde(default)]
    pub network_settings: Option<NetworkSettings>,
}

/// Files read from a container.
pub struct ContainerFiles {
    pub os_release: [&'static str; 2],
    pub dpkg: &'static str,
    pub apk: &'static str,
}

/// Files read from a container, by absolute path in it.
pub const CONTAINER_FILES: ContainerFiles =
    ContainerFiles { os_release: ["/etc/os-release", "/usr/lib/os-release"], dpkg: "/var/lib/dpkg/status", apk: "/lib/apk/db/installed" };

/// `registry/org/name:tag@digest` → repository basename and tag (or the digest's first 19 characters, or `latest`).
fn image_name(reference: &str) -> (String, String) {
    let mut at = reference.split('@');
    let repo = at.next().unwrap_or_default();
    let digest = non_empty(at.next());
    let tag = repo.rfind(':').map(|i| &repo[i + 1..]).filter(|t| !t.is_empty() && !t.contains('/'));
    let without_tag = tag.map_or(repo, |t| &repo[..repo.len() - t.len() - 1]);
    let name = without_tag.rsplit('/').next().unwrap_or_default().to_string();
    let version = tag.map(str::to_string).unwrap_or_else(|| digest.map_or_else(|| "latest".to_string(), |d| d.chars().take(19).collect()));
    (name, version)
}

const CONTAINER_ENV_RISK: &str = "Readable by anyone with Docker access (docker inspect) and by every process in the container; listed so a breach of the image, a package in it or the host shows what to rotate";

fn signal(host: &str, r#where: &str, kind: VendorSignalKind, value: String, path: Option<&str>) -> VendorSignal {
    VendorSignal { host: host.to_string(), r#where: r#where.to_string(), kind, value, path: path.map(str::to_string), collector: None }
}

/// Service-domain suffixes seen in text; only the suffix, since the full hostname can carry an account id.
pub fn hostname_signals(text: &str, host: &str, r#where: &str, path: Option<&str>) -> Vec<VendorSignal> {
    // ASCII-only, case-insensitive: the TS regex has no `u` flag.
    let vendor_host = re!(
        r"(?i-u)[a-z0-9.-]+\.(supabase\.co|neon\.tech|psdb\.cloud|mongodb\.net|upstash\.io|turso\.io|railway\.app|amazonaws\.com|digitaloceanspaces\.com|r2\.cloudflarestorage\.com|azurewebsites\.net|run\.app|firebaseio\.com)\b"
    );
    let suffixes: IndexSet<String> = vendor_host.captures_iter(text).map(|m| m[1].to_lowercase()).collect();
    suffixes.into_iter().map(|value| signal(host, r#where, VendorSignalKind::Hostname, value, path)).collect()
}

/// Variable names (never values) of `NAME=value` entries, plus the service domains in their values.
pub fn env_signals<S: AsRef<str>>(entries: &[S], host: &str, r#where: &str, path: Option<&str>) -> Vec<VendorSignal> {
    let mut names: IndexSet<String> = IndexSet::new();
    let mut values: Vec<&str> = Vec::new();
    for entry in entries {
        let Some(m) = jsre!(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=([^\n\r\x{2028}\x{2029}]*)$").captures(entry.as_ref()) else { continue };
        let name = m.get(1).map_or("", |g| g.as_str());
        if re!(r"^(PATH|HOME|HOSTNAME|LANG|LC_[A-Za-z0-9_]+|TERM|PWD|SHLVL|[A-Z0-9_]*_VERSION)$").is_match(name) {
            continue;
        }
        names.insert(name.to_string());
        values.push(m.get(2).map_or("", |g| g.as_str()));
    }
    let mut out: Vec<VendorSignal> = names.into_iter().map(|value| signal(host, r#where, VendorSignalKind::Env, value, path)).collect();
    out.extend(hostname_signals(&values.join("\n"), host, r#where, path));
    out
}

/// Signals from a compose or env file: keys (`KEY=…`, `- KEY=…`, compose `KEY: …`) and service domains.
/// `env`: the file holds `NAME=value` lines (defaults to `is_env_file(path)`).
pub fn file_signals(path: &str, text: &str, host: &str, r#where: &str, env: Option<bool>) -> Vec<VendorSignal> {
    let env = env.unwrap_or_else(|| is_env_file(path));
    let entries: Vec<String> = if env {
        text.split('\n').map(str::to_string).collect()
    } else {
        jsre!(r#"(?m)^\s*-?\s*["']?([A-Z_][A-Z0-9_]*)["']?\s*[:=]"#).captures_iter(text).map(|m| format!("{}=", &m[1])).collect()
    };
    let mut out: Vec<VendorSignal> = env_signals(&entries, host, r#where, Some(path)).into_iter().filter(|s| s.kind == VendorSignalKind::Env).collect();
    out.extend(hostname_signals(text, host, r#where, Some(path)));
    out
}

pub fn dedupe_signals(signals: Vec<VendorSignal>) -> Vec<VendorSignal> {
    let mut seen = HashSet::new();
    signals
        .into_iter()
        .filter(|s| {
            let kind = match s.kind {
                VendorSignalKind::Env => "env",
                VendorSignalKind::File => "file",
                VendorSignalKind::Deployment => "deployment",
                VendorSignalKind::Hostname => "hostname",
            };
            seen.insert([s.r#where.as_str(), kind, s.value.as_str(), s.path.as_deref().unwrap_or("")].join("\0"))
        })
        .collect()
}

/// What a container's inventory is built from besides `docker inspect`.
#[derive(Debug, Clone, Default)]
pub struct ContainerInput {
    /// Its image's env.
    pub image_env: Option<Vec<String>>,
    /// The raw files read from it (os-release, dpkg status, apk db, lockfiles), by absolute path in it.
    pub files: IndexMap<String, String>,
    /// The optional exec probe's output.
    pub probe: Option<String>,
}

/// One container → items, its service and its env secrets.
pub fn container_inventory(host: &str, c: &ContainerInspect, input: &ContainerInput) -> Collected {
    let name = c.name.strip_prefix('/').unwrap_or(&c.name);
    let where_ = format!("container:{name}");
    let running = c.state.status == "running";
    let empty_labels = IndexMap::new();
    let labels = c.config.labels.as_ref().unwrap_or(&empty_labels);
    let env: &[String] = c.config.env.as_deref().unwrap_or_default();
    let kept = kept_env(Some(env));
    let hosts = kept
        .iter()
        .filter(|e| e.starts_with("VIRTUAL_HOST=") || e.starts_with("LETSENCRYPT_HOST="))
        .flat_map(|e| e[e.find('=').map_or(0, |i| i + 1)..].split(','))
        .map(|h| js_trim(h).to_string())
        .filter(|h| !h.is_empty());
    let loopback = re!(r"^(127\.|::1$|\[::1\]|::ffff:127\.|\[::ffff:127\.|localhost)");
    let ports = c.network_settings.iter().filter_map(|n| n.ports.as_ref()).flatten().flat_map(|(port, binds)| {
        binds
            .iter()
            .flatten()
            .filter(|b| !loopback.is_match(&b.host_ip))
            .map(move |b| format!("{}:{}->{port}", if b.host_ip.is_empty() { "0.0.0.0" } else { b.host_ip.as_str() }, b.host_port))
    });
    let exposed: Vec<String> = hosts.chain(ports).collect::<IndexSet<_>>().into_iter().collect();
    let service = ServiceInfo {
        host: host.to_string(),
        r#where: where_.clone(),
        image: Some(c.config.image.clone()),
        state: c.state.status.clone(),
        exposed,
        restart: c.host_config.as_ref().and_then(|h| h.restart_policy.as_ref()).and_then(|r| r.name.clone()).filter(|n| !n.is_empty()),
        compose: labels.get("com.docker.compose.project.working_dir").cloned().filter(|n| !n.is_empty()),
        collector: None,
    };
    let base = Base { host, r#where: &where_, ecosystem: None, running: Some(running) };
    let files = &input.files;
    let os_release = CONTAINER_FILES.os_release.iter().filter_map(|p| files.get(*p)).find(|t| !t.is_empty()).map_or("", String::as_str);
    let eco = osv_ecosystem(os_release);
    let pkg_base = Base { ecosystem: eco.as_deref(), ..base };
    let (image, tag) = image_name(&c.config.image);
    let mut image_item = base.item(ItemKind::Image, image, tag);
    image_item.path = Some(c.config.image.clone());
    let mut items = vec![image_item];
    items.extend(os_item(os_release, base));
    items.extend(dpkg_status_items(files.get(CONTAINER_FILES.dpkg).map_or("", String::as_str), pkg_base));
    items.extend(apk_items(files.get(CONTAINER_FILES.apk).map_or("", String::as_str), pkg_base));
    items.extend(env_runtimes(kept.iter().copied().chain(kept_env(input.image_env.as_deref())), base));
    items.extend(probe_items(input.probe.as_deref().unwrap_or(""), base));
    // An official runtime image that declares no version in its env (`oven/bun`): the version its tag names.
    for (name, version) in image_runtimes(&c.config.image) {
        if !items.iter().any(|i| i.kind == ItemKind::Runtime && i.name == name) {
            let mut item = base.item(ItemKind::Runtime, name, version);
            item.path = Some(format!("image tag: {}", c.config.image));
            items.push(item);
        }
    }
    for (path, text) in files {
        if path == CONTAINER_FILES.dpkg || path == CONTAINER_FILES.apk || CONTAINER_FILES.os_release.contains(&path.as_str()) {
            continue;
        }
        for p in parse_lockfile(path, text) {
            let mut item = base.item(ItemKind::Package, p.name, p.version);
            item.ecosystem = Some(p.ecosystem);
            item.dev = p.dev;
            item.path = Some(path.clone());
            items.push(item);
        }
    }
    let secrets = env_secrets(env)
        .into_iter()
        .map(|s| SecretFinding {
            host: host.to_string(),
            r#where: where_.clone(),
            location: "env".to_string(),
            line: None,
            commit: None,
            kind: "env-var".to_string(),
            providers: providers_of("env-var", Some(&s.name)),
            name: Some(s.name),
            fingerprint: Some(s.fingerprint),
            exposure: Exposure::ContainerEnv,
            risk: CONTAINER_ENV_RISK.to_string(),
            collector: None,
        })
        .collect();
    Collected { items: dedupe(items), services: vec![service], secrets, signals: dedupe_signals(env_signals(env, host, &where_, None)), warnings: Vec::new() }
}

/// A regular file of a tar archive.
#[derive(Debug, Clone)]
pub struct TarEntry<'a> {
    pub name: String,
    pub data: &'a [u8],
}

/// Regular files of a tar archive (ustar/GNU, including GNU long names).
pub fn read_tar(buffer: &[u8]) -> Vec<TarEntry<'_>> {
    let mut out = Vec::new();
    // A NUL-terminated field.
    let field = |start: usize, length: usize| -> String {
        let raw = buffer.get(start..(start + length).min(buffer.len())).unwrap_or_default();
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(&raw[..end]).into_owned()
    };
    let mut offset = 0usize;
    let mut long_name: Option<String> = None;
    while offset + 512 <= buffer.len() {
        if buffer[offset..offset + 512].iter().all(|&b| b == 0) {
            break;
        }
        let size_text = field(offset + 124, 12);
        let digits: String = size_text.trim().chars().take_while(|c| ('0'..='7').contains(c)).collect();
        let kind = match buffer[offset + 156] {
            0 => b'0',
            b => b,
        };
        let prefix = if field(offset + 257, 6).starts_with("ustar") { field(offset + 345, 155) } else { String::new() };
        let name = long_name.take().unwrap_or_else(|| if prefix.is_empty() { field(offset, 100) } else { format!("{prefix}/{}", field(offset, 100)) });
        // A size that is not octal ends the archive (the TS's NaN offset): the entry is kept, empty.
        let parsed = if size_text.trim().is_empty() { Some(0) } else { usize::from_str_radix(&digits, 8).ok() };
        let Some(size) = parsed else {
            if kind == b'0' || kind == b'7' {
                out.push(TarEntry { name, data: &[] });
            }
            break;
        };
        let start = offset + 512;
        let data = &buffer[start.min(buffer.len())..start.saturating_add(size).min(buffer.len())];
        if kind == b'L' {
            let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
            long_name = Some(String::from_utf8_lossy(&data[..end]).into_owned());
        } else if kind == b'0' || kind == b'7' {
            out.push(TarEntry { name, data });
        }
        offset = start.saturating_add(size.div_ceil(512).saturating_mul(512));
    }
    out
}

/// Docker's multiplexed stdout/stderr stream (8-byte frame headers); a TTY stream passes through.
pub fn demux(buffer: &[u8]) -> String {
    if buffer.len() < 8 || buffer[0] > 2 || buffer[1] != 0 || buffer[2] != 0 || buffer[3] != 0 {
        return String::from_utf8_lossy(buffer).into_owned();
    }
    let mut parts = Vec::with_capacity(buffer.len());
    let mut offset = 0usize;
    while offset + 8 <= buffer.len() {
        let size = u32::from_be_bytes([buffer[offset + 4], buffer[offset + 5], buffer[offset + 6], buffer[offset + 7]]) as usize;
        parts.extend_from_slice(&buffer[offset + 8..(offset + 8).saturating_add(size).min(buffer.len())]);
        offset = offset.saturating_add(8).saturating_add(size);
    }
    String::from_utf8_lossy(&parts).into_owned()
}

fn is_compose_file(base: &str) -> bool {
    re!(r"^(docker-)?compose[A-Za-z0-9_.-]*\.ya?ml$").is_match(base)
}

/// Files worth a secret scan in a project dir: compose files and real (non-example) env files.
pub fn scan_file(base: &str) -> bool {
    is_compose_file(base) || is_env_file(base)
}

/// A text to secret-scan: where it came from and why holding a secret there is a risk.
#[derive(Debug, Clone)]
pub struct TextSource {
    pub r#where: String,
    pub location: String,
    pub text: String,
    pub exposure: Exposure,
    pub risk: String,
    /// Holds `NAME=value` lines (defaults to `is_env_file(location)`).
    pub env: Option<bool>,
}

/// A compose `environment:` line as a `NAME=value` entry: `- KEY: value` / `KEY: value` → `KEY=value`.
/// A value starting with a YAML indicator (`|>&*{[`) is not a literal, so it is left alone.
fn compose_entry(raw: &str) -> String {
    let line = jsre!(r"^\s*-?\s*").replace(raw, "");
    let Some(m) = jsre!(r#"^["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*:(\s+)"#).captures(&line) else { return line.into_owned() };
    let (name, run) = (&m[1], m.get(2).expect("group 2 always participates"));
    // The TS has `:\s+(?![|>&*{[])`: when the character after the whitespace is an indicator, `\s+`
    // gives one character back (which is whitespace, so the lookahead then holds) unless it is the only one.
    let consumed = if line[run.end()..].starts_with(['|', '>', '&', '*', '{', '[']) {
        let last = run.as_str().chars().next_back().map_or(0, char::len_utf8);
        if run.as_str().chars().count() < 2 {
            return line.into_owned();
        }
        run.len() - last
    } else {
        run.len()
    };
    format!("{name}={}", &line[run.start() + consumed..])
}

/// gitleaks over each text (one stdin run each), plus `NAME=value` env entries
/// in env files that gitleaks' rules miss (a DATABASE_URL with a password).
/// gitleaks missing → one warning, env-file entries still listed.
pub fn scan_secrets(host: &str, sources: &[TextSource], warnings: &mut Vec<String>) -> Vec<SecretFinding> {
    let mut out = Vec::new();
    let mut missing = false;
    for source in sources {
        let finding = |line: Option<u32>, kind: String, name: Option<String>, fingerprint: String, providers: Vec<String>| SecretFinding {
            host: host.to_string(),
            r#where: source.r#where.clone(),
            location: source.location.clone(),
            line,
            commit: None,
            kind,
            name,
            fingerprint: Some(fingerprint),
            exposure: source.exposure,
            risk: source.risk.clone(),
            providers,
            collector: None,
        };
        let mut lines: HashSet<u32> = HashSet::new();
        if !missing {
            match scan_text(&source.text) {
                Ok(hits) => {
                    for hit in hits {
                        let line = hit.line.filter(|l| *l != 0);
                        lines.extend(line);
                        let providers = providers_of(&hit.rule, hit.name.as_deref());
                        out.push(finding(line, hit.rule, hit.name, hit.fingerprint, providers));
                    }
                }
                Err(error) if error.downcast_ref::<GitleaksMissing>().is_some() => {
                    missing = true;
                    warnings.push(error.to_string());
                }
                Err(error) => warnings.push(format!("{} {}: {error}", source.r#where, source.location)),
            }
        }
        // Env files, and compose files' `environment:` entries written as literals (`KEY: value`, `- KEY=value`):
        // gitleaks' generic rule needs entropy, so a plain password typed into compose would slip through.
        let compose = is_compose_file(source.location.rsplit('/').next().unwrap_or_default());
        if !source.env.unwrap_or_else(|| is_env_file(&source.location)) && !compose {
            continue;
        }
        for (i, raw) in source.text.split('\n').enumerate() {
            let number = u32::try_from(i + 1).unwrap_or(u32::MAX);
            if lines.contains(&number) {
                continue;
            }
            let entry = if compose { compose_entry(raw) } else { jsre!(r"^\s*export\s+").replace(raw, "").into_owned() };
            for s in env_secrets(&[entry]) {
                let providers = providers_of("env-var", Some(&s.name));
                out.push(finding(Some(number), "env-var".to_string(), Some(s.name), s.fingerprint, providers));
            }
        }
    }
    out
}

pub fn host_file_risk(world_readable: bool) -> &'static str {
    if world_readable {
        "World-readable file on the host (mode o+r): any local user or compromised process can read it; rotate if the host or a service on it is breached, and chmod 600"
    } else {
        "Stored in a file on the host: whoever compromises the host or a service running as its owner can read it"
    }
}

pub const LOG_RISK: &str = "Printed into the container log: readable by anyone with Docker access and by log shipping/backup; rotate it and stop logging it";
