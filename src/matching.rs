// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! Matching advisories against the inventory: OSV settles package versions
//! deterministically, the Node index by semver; prose advisories (CERT-EU, KEV,
//! vendor announcements, CA incidents) match by product name and, with a
//! classifier.dev key, go to its classifier only when a product we run is named.

use std::time::Duration;

use anyhow::{Result, bail};
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config::ClassifierConfig;
use crate::feeds::{NodeIndexEntry, ProseItem};
use crate::http::{Fetch, Request};
use crate::name::USER_AGENT;
use crate::secrets::SecretFinding;
use crate::state::glob_match;
use crate::types::{Inventory, InventoryItem, ItemKind, ServiceInfo};
use crate::versions::satisfies;
use crate::watch::Place;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Unknown => "unknown",
        }
    }

    /// The exact lower-case label (`"high"`), nothing else.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "critical" => Some(Self::Critical),
            "high" => Some(Self::High),
            "medium" => Some(Self::Medium),
            "low" => Some(Self::Low),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }

    /// `critical` 4 … `unknown` 0: the order `at_least` compares by.
    pub fn rank(self) -> u8 {
        match self {
            Self::Critical => 4,
            Self::High => 3,
            Self::Medium => 2,
            Self::Low => 1,
            Self::Unknown => 0,
        }
    }
}

/// `severity` is as serious as `floor` or more.
pub fn at_least(severity: Severity, floor: Severity) -> bool {
    severity.rank() >= floor.rank()
}

/// One inventory item an advisory touches, with what makes it matter.
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    pub item: InventoryItem,
    /// Public hostnames and ports of the place the item lives in (never for a runtime installed on a host).
    pub exposed: Vec<String>,
    /// The place matches a `priority` glob.
    pub priority: bool,
    /// Fixed versions the advisory names for it.
    pub fixed_in: Option<Vec<String>>,
    /// The library it carries built in that the advisory is about (`BUNDLED`): its own version is not that library's.
    pub carries: Option<String>,
}

pub fn describe_target(t: &Target) -> String {
    let item = &t.item;
    let mut out = format!("{} {} {} {}", item.host, item.r#where, item.name, item.version);
    // Where a repo's item, or a package on a server (a venv, a lockfile in a container), was read.
    if (item.r#where.starts_with("repo:") || item.kind == ItemKind::Package)
        && let Some(path) = item.path.as_deref().filter(|p| !p.is_empty())
    {
        out.push_str(&format!(" ({path})"));
    }
    if item.running == Some(false) {
        out.push_str(" (stopped)");
    }
    if item.dev == Some(true) {
        out.push_str(" (dev only)");
    }
    if let Some(library) = &t.carries {
        out.push_str(&format!(" (bundles {library})"));
    }
    if !t.exposed.is_empty() {
        out.push_str(&format!(" exposed: {}", t.exposed.join(", ")));
    }
    if t.priority {
        out.push_str(" [priority]");
    }
    if let Some(fixed) = t.fixed_in.as_deref().filter(|f| !f.is_empty()) {
        out.push_str(&format!(" fixed in {}", fixed.join(" / ")));
    }
    out
}

/// A place's own name (`acme/api`, a container name) and its public hostnames, against the `priority` globs.
pub fn target_for(item: &InventoryItem, services: &[ServiceInfo], priority: &[String]) -> Target {
    let service = services.iter().find(|s| s.host == item.host && s.r#where == item.r#where);
    // A host's listeners (sshd) say nothing about a runtime binary that happens to be installed there.
    let exposed = if item.r#where == "host" && item.kind == ItemKind::Runtime { Vec::new() } else { service.map(|s| s.exposed.clone()).unwrap_or_default() };
    let mut names = vec![place_name(&item.host, &item.r#where)];
    if let Some(service) = service {
        names.extend(service.exposed.iter().cloned());
    }
    let priority = names.iter().any(|name| priority.iter().any(|pattern| glob_match(pattern, name)));
    Target { item: item.clone(), exposed, priority, fixed_in: None, carries: None }
}

/// What `priority`, `actOn`, `updateExcept` and runbook names match: a repo's `owner/name`, a container or unit name, or for a server's own packages, its collector name (`web1`).
pub fn place_name(host: &str, r#where: &str) -> String {
    if r#where == "host" {
        return host.to_string();
    }
    // `^\w+:` with ASCII `\w`: strip a leading `repo:`, `container:`, `service:`.
    let word = r#where.bytes().take_while(|b| b.is_ascii_alphanumeric() || *b == b'_').count();
    if word > 0 && r#where.as_bytes().get(word) == Some(&b':') { r#where[word + 1..].to_string() } else { r#where.to_string() }
}

// ---------- OSV ----------

/// OSV bucket directory → inventory ecosystems it covers (`Ubuntu` covers `Ubuntu:24.04:LTS`).
pub fn osv_family(ecosystem: &str) -> &str {
    ecosystem.split(':').next().unwrap_or("")
}

/// An OSV vulnerability id with the inventory items its query matched.
#[derive(Debug, Clone)]
pub struct OsvHit {
    pub id: String,
    pub modified: String,
    pub items: Vec<InventoryItem>,
}

#[derive(Deserialize)]
struct BatchVuln {
    id: String,
    #[serde(default)]
    modified: String,
}

#[derive(Deserialize, Default)]
struct BatchResult {
    #[serde(default)]
    vulns: Option<Vec<BatchVuln>>,
}

#[derive(Deserialize)]
struct BatchResponse {
    #[serde(default)]
    results: Option<Vec<BatchResult>>,
}

/// One OSV `querybatch` call per 1000 distinct (ecosystem, name, version) coordinates of the given families, in order.
/// Hits come back in the order OSV reports them, each with every item that carries the coordinate.
pub fn osv_query(inventory: &Inventory, families: &[String], fetch: &dyn Fetch) -> Result<IndexMap<String, OsvHit>> {
    struct Coordinate<'a> {
        ecosystem: &'a str,
        name: &'a str,
        version: &'a str,
        items: Vec<&'a InventoryItem>,
    }
    let mut coordinates: IndexMap<(&str, &str, &str), Coordinate> = IndexMap::new();
    for item in &inventory.items {
        let Some(ecosystem) = item.ecosystem.as_deref().filter(|e| !e.is_empty()) else { continue };
        if !families.iter().any(|f| f == osv_family(ecosystem)) {
            continue;
        }
        coordinates
            .entry((ecosystem, item.name.as_str(), item.version.as_str()))
            .or_insert_with(|| Coordinate { ecosystem, name: &item.name, version: &item.version, items: Vec::new() })
            .items
            .push(item);
    }
    let list: Vec<&Coordinate> = coordinates.values().collect();
    let mut hits: IndexMap<String, OsvHit> = IndexMap::new();
    for batch in list.chunks(1000) {
        let queries: Vec<Value> = batch.iter().map(|c| json!({ "package": { "ecosystem": c.ecosystem, "name": c.name }, "version": c.version })).collect();
        let body = serde_json::to_vec(&json!({ "queries": queries }))?;
        let request = Request::post("https://api.osv.dev/v1/querybatch", body).header("Content-Type", "application/json").timeout(Duration::from_secs(120));
        let response = fetch.fetch(request)?;
        if !response.ok() {
            bail!("OSV querybatch HTTP {}", response.status);
        }
        let data: BatchResponse = response.json()?;
        for (index, result) in data.results.unwrap_or_default().into_iter().enumerate() {
            for vuln in result.vulns.unwrap_or_default() {
                let hit = hits.entry(vuln.id.clone()).or_insert_with(|| OsvHit { id: vuln.id, modified: vuln.modified, items: Vec::new() });
                if let Some(coordinate) = batch.get(index) {
                    hit.items.extend(coordinate.items.iter().map(|i| (*i).clone()));
                }
            }
        }
    }
    Ok(hits)
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OsvSeverity {
    #[serde(rename = "type", default)]
    pub r#type: String,
    #[serde(default)]
    pub score: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OsvDatabaseSpecific {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OsvPackage {
    #[serde(default)]
    pub ecosystem: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OsvRange {
    #[serde(rename = "type", default)]
    pub r#type: String,
    /// `{ "introduced": "0" }`, `{ "fixed": "1.2.3" }`, …
    #[serde(default)]
    pub events: Vec<IndexMap<String, String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OsvEcosystemSpecific {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urgency: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OsvAffected {
    #[serde(default)]
    pub package: OsvPackage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ranges: Option<Vec<OsvRange>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub versions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystem_specific: Option<OsvEcosystemSpecific>,
}

/// An OSV vulnerability record; its field names are OSV's (snake_case), not camelCase.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OsvRecord {
    pub id: String,
    #[serde(default)]
    pub modified: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aliases: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Vec<OsvSeverity>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_specific: Option<OsvDatabaseSpecific>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affected: Option<Vec<OsvAffected>>,
}

/// JS `encodeURIComponent`: everything but `A-Z a-z 0-9 - _ . ! ~ * ' ( )` is percent-encoded (UTF-8).
fn encode_uri_component(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn osv_record(id: &str, fetch: &dyn Fetch) -> Result<OsvRecord> {
    let response = fetch.fetch(Request::get(format!("https://api.osv.dev/v1/vulns/{}", encode_uri_component(id))).timeout(Duration::from_secs(30)))?;
    if !response.ok() {
        bail!("OSV {id} HTTP {}", response.status);
    }
    response.json()
}

/// CVSS 3 weights of AV, AC, UI and C/I/A by metric value; an unknown value weighs 0 (JS `?? 0`).
fn cvss3_weight(metric: &str, value: Option<&str>) -> f64 {
    let Some(value) = value else { return 0.0 };
    match (metric, value) {
        ("AV", "N") => 0.85,
        ("AV", "A") => 0.62,
        ("AV", "L") => 0.55,
        ("AV", "P") => 0.2,
        ("AC", "L") => 0.77,
        ("AC", "H") => 0.44,
        ("UI", "N") => 0.85,
        ("UI", "R") => 0.62,
        ("C" | "I" | "A", "H") => 0.56,
        ("C" | "I" | "A", "L") => 0.22,
        _ => 0.0,
    }
}

/// JS `Math.min`: NaN wins, where `f64::min` ignores it.
fn js_min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() { f64::NAN } else { a.min(b) }
}

/// CVSS v3.x base score from its vector. `None` when the vector names no `AV` or no `S`.
/// A vector with an unusable `PR` scores NaN, as the TS does.
pub fn cvss3(vector: &str) -> Option<f64> {
    // Object.fromEntries: the last occurrence of a metric wins; `K` without `:` has no value.
    let mut metrics: IndexMap<&str, Option<&str>> = IndexMap::new();
    for part in vector.split('/').skip(1) {
        let mut pieces = part.split(':');
        let key = pieces.next().unwrap_or("");
        metrics.insert(key, pieces.next());
    }
    let get = |k: &str| metrics.get(k).copied().flatten();
    if get("AV").is_none_or(str::is_empty) || get("S").is_none_or(str::is_empty) {
        return None;
    }
    let changed = get("S") == Some("C");
    let pr = match get("PR") {
        Some("N") => 0.85,
        Some("L") => {
            if changed {
                0.68
            } else {
                0.62
            }
        }
        Some("H") => {
            if changed {
                0.5
            } else {
                0.27
            }
        }
        _ => f64::NAN,
    };
    let w = |k: &str| cvss3_weight(k, get(k));
    let iss = 1.0 - (1.0 - w("C")) * (1.0 - w("I")) * (1.0 - w("A"));
    let impact = if changed { 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0) } else { 6.42 * iss };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * w("AV") * w("AC") * pr * w("UI");
    let raw = if changed { js_min(1.08 * (impact + exploitability), 10.0) } else { js_min(impact + exploitability, 10.0) };
    Some((raw * 10.0 - 1e-9).ceil() / 10.0)
}

pub(crate) fn bucket(score: f64) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else if score > 0.0 {
        Severity::Low
    } else {
        Severity::Unknown
    }
}

pub(crate) fn label(text: Option<&str>) -> Severity {
    match text.unwrap_or("").to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "moderate" | "medium" => Severity::Medium,
        "low" | "negligible" => Severity::Low,
        _ => Severity::Unknown,
    }
}

/// Highest of the record's CVSS v3 scores and its database's own label; malicious packages are critical.
pub fn osv_severity(record: &OsvRecord) -> Severity {
    if record.id.starts_with("MAL-") {
        return Severity::Critical;
    }
    let mut best = label(record.database_specific.as_ref().and_then(|d| d.severity.as_deref()));
    for s in record.severity.as_deref().unwrap_or_default() {
        let candidate = match s.r#type.as_str() {
            "CVSS_V3" => bucket(cvss3(&s.score).unwrap_or(0.0)),
            "CVSS_V4" => Severity::Unknown,
            _ => label(Some(&s.score)),
        };
        if candidate.rank() > best.rank() {
            best = candidate;
        }
    }
    best
}

/// Fixed versions the record names for these items' packages; empty when no fix exists yet.
pub fn osv_fixes(record: &OsvRecord, items: &[InventoryItem]) -> Vec<String> {
    let mut fixes: Vec<String> = Vec::new();
    for affected in record.affected.as_deref().unwrap_or_default() {
        let relevant = items.iter().any(|item| item.name == affected.package.name && item.ecosystem.as_deref() == Some(affected.package.ecosystem.as_str()));
        if !relevant {
            continue;
        }
        for range in affected.ranges.as_deref().unwrap_or_default() {
            for event in &range.events {
                if let Some(fixed) = event.get("fixed").filter(|f| !f.is_empty())
                    && !fixes.contains(fixed) {
                        fixes.push(fixed.clone());
                    }
            }
        }
    }
    fixes
}

// ---------- Node security-wg index ----------

#[derive(Debug, Clone)]
pub struct NodeIndexHit {
    pub key: String,
    pub entry: NodeIndexEntry,
    pub items: Vec<InventoryItem>,
}

/// Node runtimes in the inventory that an index entry's `vulnerable` range covers and its `patched` range does not.
/// `keys`: only these entries (default: all). A range that cannot be read matches nothing.
pub fn node_index_matches(index: &IndexMap<String, NodeIndexEntry>, inventory: &Inventory, keys: Option<&[String]>) -> Vec<NodeIndexHit> {
    let nodes: Vec<&InventoryItem> = inventory.items.iter().filter(|item| item.kind == ItemKind::Runtime && item.name == "node").collect();
    let all: Vec<String>;
    let keys = match keys {
        Some(keys) => keys,
        None => {
            all = index.keys().cloned().collect();
            &all
        }
    };
    let mut hits = Vec::new();
    for key in keys {
        let Some(entry) = index.get(key) else { continue };
        if entry.vulnerable.is_empty() {
            continue;
        }
        let patched = if entry.patched.is_empty() { "<0.0.0" } else { entry.patched.as_str() };
        let items: Vec<InventoryItem> = nodes
            .iter()
            .filter(|item| (|| Ok::<_, anyhow::Error>(satisfies(&item.version, &entry.vulnerable)? && !satisfies(&item.version, patched)?))().unwrap_or(false))
            .map(|item| (*item).clone())
            .collect();
        if !items.is_empty() {
            hits.push(NodeIndexHit { key: key.clone(), entry: entry.clone(), items });
        }
    }
    hits
}

// ---------- prose ----------

/// Inventory names → the words an advisory uses for them. Packages (lockfile deps) are OSV's job and never prose-matched.
fn aliases(name: &str) -> &'static [&'static str] {
    match name {
        "node" => &["node.js", "nodejs"],
        "bun" => &["bun"],
        "php" => &["php"],
        "python" => &["python", "cpython"],
        "deno" => &["deno"],
        "ruby" => &["ruby"],
        "go" => &["golang"],
        "java" => &["java", "openjdk"],
        "wordpress" => &["wordpress"],
        "nginx" => &["nginx"],
        "nginx-proxy" => &["nginx"],
        "httpd" => &["apache http server", "apache httpd"],
        "apache2" => &["apache http server", "apache httpd"],
        "caddy" => &["caddy"],
        "traefik" => &["traefik"],
        "haproxy" => &["haproxy"],
        "mariadb" => &["mariadb"],
        "mysql" => &["mysql"],
        "postgres" => &["postgresql", "postgres"],
        "postgresql" => &["postgresql"],
        "redis" => &["redis"],
        "valkey" => &["valkey"],
        "mongo" => &["mongodb"],
        "mongodb" => &["mongodb"],
        "memcached" => &["memcached"],
        "rabbitmq" => &["rabbitmq"],
        "elasticsearch" => &["elasticsearch"],
        "opensearch" => &["opensearch"],
        "minio" => &["minio"],
        "n8n" => &["n8n"],
        "grafana" => &["grafana"],
        "prometheus" => &["prometheus"],
        "gitea" => &["gitea"],
        "gitlab" => &["gitlab"],
        "gitlab-ce" => &["gitlab"],
        "gitlab-ee" => &["gitlab"],
        "jenkins" => &["jenkins"],
        "nextcloud" => &["nextcloud"],
        "keycloak" => &["keycloak"],
        "vaultwarden" => &["vaultwarden"],
        "uptime-kuma" => &["uptime kuma"],
        "portainer" => &["portainer"],
        "searxng" => &["searxng"],
        "ghost" => &["ghost cms"],
        "strapi" => &["strapi"],
        "directus" => &["directus"],
        "supabase" => &["supabase"],
        "metabase" => &["metabase"],
        "tomcat" => &["apache tomcat"],
        "openssh" => &["openssh"],
        "openssh-server" => &["openssh"],
        "openssl" => &["openssl"],
        "sudo" => &["sudo"],
        "glibc" => &["glibc"],
        "systemd" => &["systemd"],
        "docker.io" => &["docker engine", "docker"],
        "docker" => &["docker engine", "docker"],
        "docker-ce" => &["docker engine", "docker"],
        "containerd" => &["containerd"],
        "runc" => &["runc"],
        "curl" => &["curl", "libcurl"],
        "git" => &["git"],
        "cloudflared" => &["cloudflared", "cloudflare tunnel"],
        "ffmpeg" => &["ffmpeg"],
        "imagemagick" => &["imagemagick"],
        "sqlite3" => &["sqlite"],
        "sqlite" => &["sqlite"],
        "libxml2" => &["libxml2"],
        "libxslt" => &["libxslt"],
        "zlib" => &["zlib"],
        // Libraries runtimes and packages also carry built in (`BUNDLED`), under their distro source names.
        "brotli" => &["brotli"],
        "zstd" | "libzstd" => &["zstd", "zstandard"],
        "nghttp2" => &["nghttp2"],
        "c-ares" => &["c-ares"],
        "libuv" | "libuv1" => &["libuv"],
        "libwebp" => &["libwebp"],
        "libpng" | "libpng1.6" => &["libpng"],
        "libjpeg-turbo" => &["libjpeg-turbo"],
        "tiff" => &["libtiff"],
        "freetype" => &["freetype"],
        "xz" => &["xz utils"],
        "xz-utils" => &["xz utils"],
        "exim4" => &["exim"],
        "postfix" => &["postfix"],
        "ca-certificates" => &["ca-certificates"],
        "linux kernel" => &["linux kernel"],
        "ubuntu" => &["ubuntu"],
        "debian" => &["debian"],
        "alpine" => &["alpine linux"],
        "railway" => &["railway"],
        "vercel" => &["vercel"],
        "netlify" => &["netlify"],
        "fly" => &["fly.io"],
        "render" => &["render.com"],
        "heroku" => &["heroku"],
        "cloudflare" => &["cloudflare"],
        "firebase" => &["firebase"],
        "aws" => &["aws amplify"],
        _ => &[],
    }
}

/// Libraries that runtimes and language packages carry built in rather than take from the system: an advisory about
/// the library concerns each carrier too, at the carrier's own version. Which carrier release has the fix is the
/// responder's to read (`upstream.rs`). A carrier is `runtime:<name>` or `<OSV ecosystem>:<package>`; the library's
/// own distro package is matched by name (`aliases`).
pub const BUNDLED: &[(&str, &[&str])] = &[
    ("brotli", &["runtime:node", "runtime:bun", "PyPI:brotli", "PyPI:brotlicffi"]),
    ("zlib", &["runtime:node", "runtime:bun", "PyPI:pillow", "PyPI:grpcio"]),
    ("zstd", &["runtime:node", "runtime:bun", "PyPI:zstandard"]),
    ("openssl", &["runtime:node", "PyPI:cryptography", "PyPI:psycopg2-binary", "PyPI:psycopg-binary"]),
    ("boringssl", &["runtime:bun", "PyPI:grpcio"]),
    ("nghttp2", &["runtime:node"]),
    ("llhttp", &["runtime:node"]),
    ("c-ares", &["runtime:node", "runtime:bun", "PyPI:grpcio"]),
    ("libuv", &["runtime:node"]),
    ("v8", &["runtime:node", "runtime:deno"]),
    ("sqlite", &["runtime:node", "runtime:bun", "runtime:deno", "npm:better-sqlite3", "npm:sqlite3"]),
    ("libxml2", &["PyPI:lxml"]),
    ("libxslt", &["PyPI:lxml"]),
    ("libwebp", &["PyPI:pillow", "npm:sharp"]),
    ("libpng", &["PyPI:pillow", "npm:sharp"]),
    ("libjpeg-turbo", &["PyPI:pillow", "npm:sharp"]),
    ("libtiff", &["PyPI:pillow", "npm:sharp"]),
    ("freetype", &["PyPI:pillow"]),
];

/// A package name as its registry compares it (PyPI: case, `_` and `.` folded to `-`).
fn package_name_key(ecosystem: &str, name: &str) -> String {
    let name = name.to_lowercase();
    if osv_family(ecosystem) == "PyPI" { name.replace(['_', '.'], "-") } else { name }
}

fn is_carrier(carrier: &str, item: &InventoryItem) -> bool {
    match carrier.split_once(':') {
        Some(("runtime", name)) => item.kind == ItemKind::Runtime && item.name.eq_ignore_ascii_case(name),
        Some((ecosystem, name)) => {
            item.kind == ItemKind::Package
                && item.ecosystem.as_deref().is_some_and(|e| osv_family(e) == ecosystem && package_name_key(e, &item.name) == package_name_key(e, name))
        }
        None => false,
    }
}

/// The libraries an item carries built in.
pub fn bundled_in(item: &InventoryItem) -> Vec<&'static str> {
    BUNDLED.iter().filter(|(_, carriers)| carriers.iter().any(|c| is_carrier(c, item))).map(|(library, _)| *library).collect()
}

/// The first of `terms` that the item carries built in: what its target says it bundles.
pub fn carried(item: &InventoryItem, terms: &[String]) -> Option<String> {
    let bundled = bundled_in(item);
    terms.iter().find(|t| bundled.contains(&t.as_str())).cloned()
}

/// Library → the items that carry it built in (at most 60 per library), for the advisories that name the library.
pub fn carrier_terms(inventory: &Inventory) -> IndexMap<String, Vec<&InventoryItem>> {
    let mut terms: IndexMap<String, Vec<&InventoryItem>> = IndexMap::new();
    for item in &inventory.items {
        for library in bundled_in(item) {
            let list = terms.entry(library.to_string()).or_default();
            if list.len() < 60 {
                list.push(item);
            }
        }
    }
    terms
}

/// Product names a prose advisory could mention, each with the inventory items it stands for (at most 60 per name).
pub fn product_terms(inventory: &Inventory) -> IndexMap<String, Vec<&InventoryItem>> {
    let mut terms: IndexMap<String, Vec<&InventoryItem>> = IndexMap::new();
    for item in &inventory.items {
        if item.kind == ItemKind::Package {
            continue;
        }
        let name = if item.kind == ItemKind::Os { item.name.to_lowercase().split(' ').next().unwrap_or("").to_string() } else { item.name.clone() };
        let mut found = aliases(&name);
        if found.is_empty() {
            found = aliases(&name.to_lowercase());
        }
        for term in found {
            let list = terms.entry((*term).to_string()).or_default();
            if list.len() < 60 {
                list.push(item);
            }
        }
    }
    terms
}

#[derive(Debug, Clone)]
pub struct ProseCandidate {
    pub items: Vec<ProseItem>,
    pub terms: Vec<String>,
    pub targets: Vec<Target>,
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// `mentions` on text and term already ASCII-lower-cased.
fn mentions_lower(text: &str, term: &str) -> bool {
    let mut from = 0;
    while from <= text.len() {
        let Some(offset) = text[from..].find(term) else { return false };
        let start = from + offset;
        let end = start + term.len();
        // `(^|[^\w.-])`
        let before_ok = text[..start].chars().next_back().is_none_or(|c| !(is_word_char(c) || c == '.' || c == '-'));
        // `($|[^\w-]|-(?=\d))`
        let mut after = text[end..].chars();
        let after_ok = match after.next() {
            None => true,
            Some('-') => after.next().is_some_and(|d| d.is_ascii_digit()),
            Some(c) => !is_word_char(c),
        };
        if before_ok && after_ok {
            return true;
        }
        // Occurrences may overlap: resume one character after this start.
        from = start + text[start..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// A name followed by a version (`nginx-1.31.7`) is a mention; `nginx-proxy` is not a mention of `nginx`.
/// Case-insensitive for ASCII (the terms are ASCII product names).
pub fn mentions(text: &str, term: &str) -> bool {
    mentions_lower(&text.to_ascii_lowercase(), &term.to_ascii_lowercase())
}

/// Items naming a product we run, or a library something we run carries built in, grouped by the names they use. CA
/// incidents concern every TLS client.
pub fn prose_candidates(items: &[ProseItem], inventory: &Inventory, priority: &[String]) -> Vec<ProseCandidate> {
    let terms = product_terms(inventory);
    let carriers = carrier_terms(inventory);
    // The group's candidate with the inventory items already turned into its targets (compared by identity).
    let mut groups: IndexMap<String, (ProseCandidate, Vec<&InventoryItem>)> = IndexMap::new();
    for item in items {
        let text = format!("{} {}", item.title, item.text).to_ascii_lowercase();
        let mut hit: Vec<String> =
            terms.keys().chain(carriers.keys()).filter(|term| mentions_lower(&text, &term.to_ascii_lowercase())).cloned().collect::<IndexSet<_>>().into_iter().collect();
        // The Node blog's items name no product: it is Node's own feed.
        if item.source == "node-security-blog" {
            hit = if terms.contains_key("node.js") { vec!["node.js".to_string()] } else { Vec::new() };
        }
        if item.source == "ca-incidents" {
            hit = vec!["tls clients".to_string()];
        }
        if hit.is_empty() {
            continue;
        }
        // Each item once: as the product named when it is one, else as the carrier of a library named.
        let matched: Vec<(&InventoryItem, bool)> = if item.source == "ca-incidents" {
            inventory
                .items
                .iter()
                .filter(|i| {
                    i.kind == ItemKind::Runtime && ["node", "bun", "deno", "python", "java"].contains(&i.name.as_str())
                        || i.name == "certifi"
                        || i.name == "ca-certificates"
                })
                .map(|i| (i, false))
                .collect()
        } else {
            let products = hit.iter().flat_map(|term| terms.get(term).into_iter().flatten().map(|i| (*i, false)));
            products.chain(hit.iter().flat_map(|term| carriers.get(term).into_iter().flatten().map(|i| (*i, true)))).collect()
        };
        if matched.is_empty() {
            continue;
        }
        hit.sort();
        let key = hit.join("|");
        let (group, done) = groups.entry(key).or_insert_with(|| (ProseCandidate { items: Vec::new(), terms: hit, targets: Vec::new() }, Vec::new()));
        group.items.push(item.clone());
        for (i, carrier) in matched {
            if !done.iter().any(|d| std::ptr::eq(*d, i)) {
                done.push(i);
                let mut target = target_for(i, &inventory.services, priority);
                if carrier {
                    target.carries = carried(i, &group.terms);
                }
                group.targets.push(target);
            }
        }
    }
    groups.into_values().map(|(group, _)| group).collect()
}

// ---------- classifier ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Affected,
    NotAffected,
    Unsure,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Affected => "affected",
            Self::NotAffected => "not-affected",
            Self::Unsure => "unsure",
        }
    }
}

pub const JUDGE_INSTRUCTIONS: &str = "You triage a security advisory against the software one organisation runs (servers, Docker containers, and the code in its GitHub repos).
affected: the advisory plausibly applies to a listed item at its listed version, or the advisory gives no versions and the product is the same, or a listed item bundles the library the advisory is about (its line says \"bundles <library>\": its own version is not the library's), or it is a CA compromise/distrust affecting TLS clients' trust stores.
not-affected: the advisory is about a different product that only shares a word with a listed item, or every listed version is clearly outside the affected range, or it is routine news with no vulnerability.
unsure: you cannot tell.";

/// The first `max` UTF-16 code units of `text` (JS `slice(0, max)`), never splitting a character.
fn utf16_prefix(text: &str, max: usize) -> &str {
    let mut units = 0;
    for (index, c) in text.char_indices() {
        units += c.len_utf16();
        if units > max {
            return &text[..index];
        }
    }
    text
}

pub fn judge_input(candidate: &ProseCandidate) -> String {
    let advisories =
        candidate.items.iter().map(|item| format!("[{}] {}\n{}", item.source, item.title, utf16_prefix(&item.text, 1500))).collect::<Vec<_>>().join("\n\n");
    let targets = candidate.targets.iter().take(25).map(describe_target).collect::<Vec<_>>().join("\n");
    let more = if candidate.targets.len() > 25 { format!("\n… {} more", candidate.targets.len() - 25) } else { String::new() };
    format!("Advisory:\n{advisories}\n\nWhat we run that the advisory names ({}):\n{targets}{more}", candidate.terms.join(", "))
}

/// One classifier.dev call, with the user's key when there is one. The key goes in the header only, never in errors.
pub fn classify(config: &ClassifierConfig, labels: &[&str], instructions: &str, input: &str, fetch: &dyn Fetch) -> Result<String> {
    let body = serde_json::to_vec(&json!({ "model": config.model, "tier": config.tier, "labels": labels, "instructions": instructions, "input": input }))?;
    let mut request = Request::post(config.url.as_str(), body)
        .header("Content-Type", "application/json")
        .timeout(Duration::try_from_secs_f64(config.timeout_seconds).unwrap_or(Duration::ZERO));
    if let Some(key) = config.api_key.as_deref().filter(|k| !k.is_empty()) {
        request = request.header("Authorization", format!("Bearer {key}"));
    }
    let response = fetch.fetch(request.header("User-Agent", USER_AGENT))?;
    if !response.ok() {
        bail!("classifier HTTP {}", response.status);
    }
    let value: Value = response.json()?;
    match value.pointer("/results/0/label").and_then(Value::as_str) {
        Some(label) if labels.contains(&label) => Ok(label.to_string()),
        _ => bail!("classifier returned no valid label"),
    }
}

pub fn judge(candidate: &ProseCandidate, config: &ClassifierConfig, fetch: &dyn Fetch) -> Result<Verdict> {
    let label = classify(config, &["affected", "not-affected", "unsure"], JUDGE_INSTRUCTIONS, &judge_input(candidate), fetch)?;
    Ok(match label.as_str() {
        "affected" => Verdict::Affected,
        "not-affected" => Verdict::NotAffected,
        _ => Verdict::Unsure,
    })
}

// ---------- breach impact ----------

/// The secrets to rotate when something is compromised: those sitting in the
/// affected places (a container carrying a malicious package, a repo whose
/// dependency was hijacked), and those that unlock an affected vendor.
pub fn secrets_at_risk(inventory: &Inventory, places: &[Place], vendors: &[String]) -> Vec<SecretFinding> {
    inventory
        .secrets
        .iter()
        .filter(|s| places.iter().any(|p| p.host == s.host && p.r#where == s.r#where) || s.providers.iter().any(|p| vendors.contains(p)))
        .cloned()
        .collect()
}

pub fn describe_secret(s: &SecretFinding) -> String {
    let mut out = s.name.clone().unwrap_or_else(|| s.kind.clone());
    if let Some(fp) = s.fingerprint.as_deref().filter(|f| !f.is_empty()) {
        out.push_str(&format!(" (fp {fp})"));
    }
    out.push_str(&format!(" at {} {} {}", s.host, s.r#where, s.location));
    if let Some(line) = s.line.filter(|l| *l != 0) {
        out.push_str(&format!(":{line}"));
    }
    if let Some(commit) = s.commit.as_deref().filter(|c| !c.is_empty()) {
        out.push_str(&format!(" commit {commit}"));
    }
    out.push_str(&format!(" [{}]", s.exposure.as_str()));
    if !s.providers.is_empty() {
        out.push_str(&format!(" unlocks {}", s.providers.join(", ")));
    }
    out
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::http::Response;
    use crate::secrets::Exposure;

    fn item(host: &str, r#where: &str, kind: ItemKind, ecosystem: Option<&str>, name: &str, version: &str) -> InventoryItem {
        InventoryItem {
            host: host.into(),
            r#where: r#where.into(),
            kind,
            ecosystem: ecosystem.map(String::from),
            name: name.into(),
            version: version.into(),
            path: None,
            running: None,
            dev: None,
            collector: None,
        }
    }

    fn inventory(items: Vec<InventoryItem>) -> Inventory {
        Inventory { items, ..Inventory::default() }
    }

    #[test]
    fn cvss3_scores_known_vectors() {
        assert_eq!(cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), Some(9.8));
        // Scope changed: the classic reflected XSS, and an authenticated one with full impact.
        assert_eq!(cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), Some(6.1));
        assert_eq!(cvss3("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"), Some(9.9));
        assert_eq!(cvss3("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"), Some(7.8));
        assert_eq!(cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), Some(0.0));
        assert_eq!(cvss3("not a vector"), None);
    }

    #[test]
    fn osv_severity_takes_the_highest_signal() {
        let record = OsvRecord {
            id: "GHSA-aaaa".into(),
            database_specific: Some(OsvDatabaseSpecific { severity: Some("MODERATE".into()) }),
            severity: Some(vec![
                OsvSeverity { r#type: "CVSS_V4".into(), score: "CVSS:4.0/AV:N".into() },
                OsvSeverity { r#type: "CVSS_V3".into(), score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into() },
            ]),
            ..OsvRecord::default()
        };
        assert_eq!(osv_severity(&record), Severity::Critical);
        assert_eq!(osv_severity(&OsvRecord { id: "MAL-2026-1".into(), ..OsvRecord::default() }), Severity::Critical);
        let labelled = OsvRecord { id: "X".into(), database_specific: Some(OsvDatabaseSpecific { severity: Some("moderate".into()) }), ..OsvRecord::default() };
        assert_eq!(osv_severity(&labelled), Severity::Medium);
    }

    #[test]
    fn osv_fixes_picks_only_the_packages_and_ecosystems_in_use() {
        let events = |fixed: &str| {
            vec![OsvRange {
                r#type: "ECOSYSTEM".into(),
                events: vec![IndexMap::from([("introduced".to_string(), "0".to_string())]), IndexMap::from([("fixed".to_string(), fixed.to_string())])],
            }]
        };
        let affected = |ecosystem: &str, name: &str, fixed: &str| OsvAffected {
            package: OsvPackage { ecosystem: ecosystem.into(), name: name.into() },
            ranges: Some(events(fixed)),
            ..OsvAffected::default()
        };
        let record = OsvRecord {
            id: "CVE-1".into(),
            affected: Some(vec![
                affected("npm", "acme-lib", "1.2.3"),
                affected("PyPI", "acme-lib", "9.9.9"),
                affected("npm", "other", "4.0.0"),
                affected("npm", "acme-lib", "1.2.3"),
            ]),
            ..OsvRecord::default()
        };
        let items = [item("github", "repo:acme/api", ItemKind::Package, Some("npm"), "acme-lib", "1.0.0")];
        assert_eq!(osv_fixes(&record, &items), vec!["1.2.3"]);
        assert!(osv_fixes(&record, &[item("h", "host", ItemKind::OsPackage, Some("Debian:13"), "acme-lib", "1")]).is_empty());
    }

    #[test]
    fn mentions_does_not_match_inside_a_longer_word() {
        assert!(mentions("A flaw in nginx allows", "nginx"));
        assert!(mentions("NGINX.", "nginx"));
        assert!(mentions("fixed in nginx-1.31.7 today", "nginx"));
        assert!(mentions("nginx", "nginx"));
        assert!(!mentions("the nginx-proxy image", "nginx"));
        assert!(!mentions("denginx and nginxy", "nginx"));
        assert!(!mentions("see my.nginx and re-nginx", "nginx"));
        assert!(!mentions("nginx_plus", "nginx"));
        // A rejected first occurrence does not hide a later one.
        assert!(mentions("nginx-proxy, then nginx 1.2", "nginx"));
        assert!(!mentions("aaa", "aa"));
        assert!(mentions("xaa aa", "aa"));
    }

    #[test]
    fn node_index_matches_vulnerable_unpatched_nodes() {
        let mut index = IndexMap::new();
        index.insert(
            "1".to_string(),
            NodeIndexEntry {
                cve: vec!["CVE-1".into()],
                vulnerable: "<20.11.1 || >=21.0.0 <21.6.2".into(),
                patched: ">=20.11.1 <21.0.0 || >=21.6.2".into(),
                ..Default::default()
            },
        );
        index.insert("2".to_string(), NodeIndexEntry { vulnerable: "<18.0.0".into(), ..Default::default() });
        index.insert("3".to_string(), NodeIndexEntry { vulnerable: String::new(), ..Default::default() });
        let inv = inventory(vec![
            item("web1", "host", ItemKind::Runtime, None, "node", "20.10.0"),
            item("web1", "container:web", ItemKind::Runtime, None, "node", "20.11.1"),
            item("web1", "container:old", ItemKind::Runtime, None, "node", "16.0.0"),
            item("web1", "host", ItemKind::Runtime, None, "bun", "1.0.0"),
        ]);
        let hits = node_index_matches(&index, &inv, None);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].key, "1");
        assert_eq!(hits[0].items.iter().map(|i| i.version.as_str()).collect::<Vec<_>>(), vec!["20.10.0", "16.0.0"]);
        // Entry 2 has no patched range: every node below 18 matches.
        assert_eq!(hits[1].key, "2");
        assert_eq!(hits[1].items[0].version, "16.0.0");
        let only = node_index_matches(&index, &inv, Some(&["2".to_string(), "missing".to_string()]));
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].key, "2");
    }

    #[test]
    fn prose_candidates_group_by_product_and_ignore_packages() {
        let inv = inventory(vec![
            item("web1", "container:proxy", ItemKind::Image, None, "nginx", "1.27"),
            item("web1", "host", ItemKind::OsPackage, Some("Ubuntu:24.04:LTS"), "curl", "8.5"),
            item("github", "repo:acme/api", ItemKind::Package, Some("npm"), "redis", "4.0.0"),
        ]);
        let prose = |source: &str, title: &str, text: &str| ProseItem {
            source: source.into(),
            id: title.into(),
            title: title.into(),
            text: text.into(),
            url: String::new(),
            published: None,
            cves: Vec::new(),
            exploited: None,
            high_signal: false,
            changed: None,
            vendor: None,
            news: None,
        };
        let items = vec![
            prose("cert-eu", "nginx flaw", "fixed in nginx-1.27.3"),
            prose("cert-eu", "redis flaw", "redis only a package here"),
            prose("cert-eu", "nginx-proxy", "unrelated"),
        ];
        let groups = prose_candidates(&items, &inv, &["acme/*".to_string(), "proxy".to_string()]);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].terms, vec!["nginx"]);
        assert_eq!(groups[0].items.len(), 1);
        assert_eq!(groups[0].targets.len(), 1);
        assert!(groups[0].targets[0].priority);
        assert_eq!(describe_target(&groups[0].targets[0]), "web1 container:proxy nginx 1.27 [priority]");
    }

    #[test]
    fn an_advisory_naming_a_library_reaches_what_carries_it_built_in_marked_as_such() {
        let inv = inventory(vec![
            item("web1", "container:api", ItemKind::Runtime, None, "node", "22.23.2"),
            item("web1", "container:edge", ItemKind::OsPackage, Some("Alpine:v3.22"), "brotli", "1.2.0-r0"),
            item("web1", "host", ItemKind::Package, Some("PyPI"), "Brotli", "1.2.0"),
            item("web1", "host", ItemKind::Package, Some("PyPI"), "requests", "2.32.0"),
            item("web1", "container:py", ItemKind::Runtime, None, "python", "3.12.7"),
        ]);
        let advisory = ProseItem {
            source: "cert-eu".into(),
            id: "a".into(),
            title: "Brotli decoder overflow".into(),
            text: "Fixed in Brotli 1.2.1.".into(),
            url: String::new(),
            published: None,
            cves: Vec::new(),
            exploited: None,
            high_signal: true,
            changed: None,
            vendor: None,
            news: None,
        };
        let groups = prose_candidates(&[advisory], &inv, &[]);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].terms, ["brotli"]);
        let lines: Vec<String> = groups[0].targets.iter().map(describe_target).collect();
        assert_eq!(
            lines,
            ["web1 container:edge brotli 1.2.0-r0", "web1 container:api node 22.23.2 (bundles brotli)", "web1 host Brotli 1.2.0 (bundles brotli)"],
            "the distro's own build is the product; node and the PyPI binding carry it; python and requests don't"
        );
    }

    #[test]
    fn target_for_and_place_name() {
        assert_eq!(place_name("web1", "host"), "web1");
        assert_eq!(place_name("web1", "container:web"), "web");
        assert_eq!(place_name("github", "repo:acme/api"), "acme/api");
        let service = ServiceInfo {
            host: "web1".into(),
            r#where: "host".into(),
            image: None,
            state: "running".into(),
            restart: None,
            exposed: vec!["example.com".into()],
            compose: None,
            collector: None,
        };
        let runtime = target_for(&item("web1", "host", ItemKind::Runtime, None, "node", "20.0.0"), std::slice::from_ref(&service), &["example.com".to_string()]);
        assert!(runtime.exposed.is_empty());
        assert!(runtime.priority);
        let package = target_for(&item("web1", "host", ItemKind::OsPackage, None, "curl", "8"), &[service], &[]);
        assert_eq!(package.exposed, vec!["example.com"]);
        assert!(!package.priority);
    }

    fn classifier(api_key: Option<&str>) -> ClassifierConfig {
        ClassifierConfig {
            api_key: api_key.map(String::from),
            url: "https://classifier.example.com/v1".into(),
            model: "m".into(),
            tier: "free".into(),
            timeout_seconds: 5.0,
        }
    }

    fn json_response(status: u16, body: &str) -> Result<Response> {
        Ok(Response { status, headers: Vec::new(), body: body.as_bytes().to_vec() })
    }

    #[test]
    fn classify_sends_the_key_only_when_configured() {
        let seen: Mutex<Vec<Request>> = Mutex::new(Vec::new());
        let fetch = |req: Request| {
            seen.lock().unwrap().push(req);
            json_response(200, r#"{"results":[{"label":"unsure"}]}"#)
        };
        assert_eq!(classify(&classifier(None), &["affected", "unsure"], "i", "x", &fetch).unwrap(), "unsure");
        assert_eq!(classify(&classifier(Some("k-123")), &["affected", "unsure"], "i", "x", &fetch).unwrap(), "unsure");
        let seen = seen.lock().unwrap();
        assert!(!seen[0].headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("authorization")));
        assert!(seen[1].headers.contains(&("Authorization".to_string(), "Bearer k-123".to_string())));
        let body: Value = serde_json::from_slice(seen[0].body.as_deref().unwrap()).unwrap();
        assert_eq!(body, json!({ "model": "m", "tier": "free", "labels": ["affected", "unsure"], "instructions": "i", "input": "x" }));
    }

    #[test]
    fn classify_rejects_failures_and_foreign_labels() {
        let server_error = |_: Request| json_response(503, "");
        assert_eq!(classify(&classifier(None), &["affected"], "i", "x", &server_error).unwrap_err().to_string(), "classifier HTTP 503");
        let foreign = |_: Request| json_response(200, r#"{"results":[{"label":"maybe"}]}"#);
        assert_eq!(classify(&classifier(None), &["affected"], "i", "x", &foreign).unwrap_err().to_string(), "classifier returned no valid label");
    }

    #[test]
    fn osv_query_batches_and_merges_items_by_vulnerability() {
        let inv = inventory(vec![
            item("web1", "host", ItemKind::OsPackage, Some("Ubuntu:24.04:LTS"), "curl", "8.5"),
            item("web1", "container:a", ItemKind::OsPackage, Some("Ubuntu:24.04:LTS"), "curl", "8.5"),
            item("github", "repo:acme/api", ItemKind::Package, Some("npm"), "left-pad", "1.0.0"),
            item("github", "repo:acme/api", ItemKind::Package, Some("PyPI"), "requests", "2.0.0"),
        ]);
        let requests: Mutex<Vec<Value>> = Mutex::new(Vec::new());
        let fetch = |req: Request| {
            assert_eq!(req.url, "https://api.osv.dev/v1/querybatch");
            requests.lock().unwrap().push(serde_json::from_slice(req.body.as_deref().unwrap()).unwrap());
            json_response(
                200,
                r#"{"results":[{"vulns":[{"id":"CVE-1","modified":"t1"}]},{"vulns":[{"id":"CVE-1","modified":"t1"},{"id":"CVE-2","modified":"t2"}]},{}]}"#,
            )
        };
        let hits = osv_query(&inv, &["Ubuntu".to_string(), "npm".to_string()], &fetch).unwrap();
        let sent = requests.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0]["queries"].as_array().unwrap().len(), 2);
        assert_eq!(sent[0]["queries"][0], json!({ "package": { "ecosystem": "Ubuntu:24.04:LTS", "name": "curl" }, "version": "8.5" }));
        assert_eq!(hits.keys().collect::<Vec<_>>(), vec!["CVE-1", "CVE-2"]);
        assert_eq!(hits["CVE-1"].items.len(), 3);
        assert_eq!(hits["CVE-2"].items.len(), 1);
        let failing = |_: Request| json_response(500, "");
        assert_eq!(osv_query(&inv, &["npm".to_string()], &failing).unwrap_err().to_string(), "OSV querybatch HTTP 500");
    }

    #[test]
    fn describe_secret_and_secrets_at_risk() {
        let secret = |where_: &str, providers: &[&str]| SecretFinding {
            host: "web1".into(),
            r#where: where_.into(),
            location: "env".into(),
            line: None,
            commit: None,
            kind: "env-var".into(),
            name: Some("API_KEY".into()),
            fingerprint: Some("abcd1234".into()),
            exposure: Exposure::ContainerEnv,
            risk: String::new(),
            providers: providers.iter().map(|p| p.to_string()).collect(),
            collector: None,
        };
        let inv = Inventory { secrets: vec![secret("container:a", &[]), secret("container:b", &["aws"]), secret("container:c", &[])], ..Inventory::default() };
        let at_risk = secrets_at_risk(&inv, &[Place { host: "web1".into(), r#where: "container:a".into() }], &["aws".to_string()]);
        assert_eq!(at_risk.iter().map(|s| s.r#where.as_str()).collect::<Vec<_>>(), vec!["container:a", "container:b"]);
        assert_eq!(describe_secret(&inv.secrets[1]), "API_KEY (fp abcd1234) at web1 container:b env [container-env] unlocks aws");
    }

    #[test]
    fn judge_input_truncates_by_utf16_units() {
        assert_eq!(utf16_prefix("abc", 2), "ab");
        assert_eq!(utf16_prefix("a😀", 2), "a");
        assert_eq!(utf16_prefix("a😀", 3), "a😀");
    }
}
