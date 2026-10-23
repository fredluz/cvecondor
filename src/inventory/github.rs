// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! The user's GitHub repos through the REST API, default branch only: what each
//! repo declares it runs (lockfiles, manifests, Dockerfiles, compose, version
//! files, deploy configs), the secrets sitting in its files (committed env
//! files, gitleaks over credential-prone files), its Actions secret names and
//! vendor signals. GET requests only. A repo whose pushed_at hasn't moved costs
//! no request beyond the listing; a changed one refetches only changed blobs.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

use anyhow::{Result, anyhow, bail};
use indexmap::{IndexMap, IndexSet};
use jiff::Timestamp;
use regex::Regex;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::config::GithubCollector;
use crate::fixes::image_env;
use crate::http::{Fetch, Request, Response};
use crate::inventory::CollectContext;
use crate::inventory::system::{Base, dedupe, env_runtimes, kept_env};
use crate::manifests::{LOCKFILES, RepoFinding, RepoFindingKind, image_references, is_repo_file, is_vendored, names_images, parse_repo_file};
use crate::name::USER_AGENT;
use crate::secrets::{Exposure, SecretFinding, env_secrets, gitleaks_available, is_env_file, providers_of, scan_text};
use crate::state::{glob_match, read_state, write_state};
use crate::types::{Collected, InventoryItem, ItemKind, VendorSignal, VendorSignalKind};
use crate::util;
use crate::vendors::catalog::vendor_file_match;

/// A repo in GitHub's listing (GitHub's snake_case names).
#[derive(Debug, Clone, Deserialize)]
pub struct Repo {
    pub full_name: String,
    #[serde(default)]
    pub private: bool,
    #[serde(default)]
    pub fork: bool,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub pushed_at: Option<String>,
    #[serde(default)]
    pub default_branch: Option<String>,
}

/// An entry of GitHub's git tree API.
#[derive(Debug, Clone, Deserialize)]
pub struct TreeEntry {
    pub path: String,
    #[serde(rename = "type")]
    pub r#type: String,
    pub sha: String,
    #[serde(default)]
    pub size: Option<u64>,
}

/// A secret in a file: name and fingerprint only, never the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hit {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlobSignalKind {
    Env,
    Hostname,
}

/// An env var name or service domain found in a file: names, never values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobSignal {
    pub kind: BlobSignalKind,
    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Blob {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub findings: Option<Vec<RepoFinding>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signals: Option<Vec<BlobSignal>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<Hit>>,
    /// The image references a Dockerfile or compose file names (`None` for other files, and for blobs cached before this was kept).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub images: Option<Vec<String>>,
    /// false: read while gitleaks was missing or failing; read again once it works.
    #[serde(default)]
    pub scanned: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoEntry {
    pub pushed_at: String,
    /// Repo-relative path → key into `blobs`.
    #[serde(default)]
    pub files: IndexMap<String, String>,
    /// Committed env files, read or not (too big, vendored).
    #[serde(default)]
    pub env_files: Vec<String>,
    #[serde(default)]
    pub vendor_files: Vec<String>,
    #[serde(default)]
    pub actions: Vec<String>,
    /// Deployment creator logins and environment names.
    #[serde(default)]
    pub deployments: Vec<String>,
    /// Facts about the repo that hold until it changes (truncated tree, files over the size cap).
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub scanned: bool,
}

/// What a registry said about an image reference's env, kept for a day so a collection does not ask again.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImageEnv {
    /// When the registry was asked, as an ISO timestamp.
    pub at: String,
    /// The `*_VERSION` variables only: the rest of an image's env can hold anything.
    #[serde(default)]
    pub env: Vec<String>,
    /// Why it could not be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `<stateDir>/<collector name>.cache.json`. Holds names, versions and fingerprints, never file contents.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Cache {
    #[serde(default)]
    pub repos: IndexMap<String, RepoEntry>,
    #[serde(default)]
    pub blobs: IndexMap<String, Blob>,
    /// Image reference → its env, as the registry last said.
    #[serde(default)]
    pub images: IndexMap<String, ImageEnv>,
}

/// Largest file read in one piece.
pub const SMALL: usize = 256 * 1024;
/// Repos read in parallel.
pub const CONCURRENCY: usize = 4;

/// The API said to stop: the rest of the repos keep their previous results.
#[derive(Debug)]
struct RateLimited(String);

impl fmt::Display for RateLimited {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RateLimited {}

/// A lazily compiled regex literal, one static per call site.
macro_rules! re {
    ($pattern:expr) => {{
        static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new($pattern).expect("valid regex"));
        &*RE
    }};
}

// The TS regexes use `\w` and `\b` (ASCII); the `regex` crate's are Unicode, so these spell the ASCII classes out.
static ENV_EXAMPLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(^|/)\.?env(\.[A-Za-z0-9_-]+)*\.(example|sample|template|dist)$").expect("valid regex"));
static WORKFLOW: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\.github/workflows/[^/]+\.ya?ml$").expect("valid regex"));
static COMPOSE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(^|/)(docker-)?compose[A-Za-z0-9_.-]*\.ya?ml$").expect("valid regex"));
/// Files that commonly hold credentials, scanned by gitleaks when small.
static SECRET_FILE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(^|/)(\.npmrc|\.pypirc|settings\.py|wp-config\.php|[^/]*\.(tfvars|tfstate|pem|key)|id_(rsa|dsa|ecdsa|ed25519)[A-Za-z0-9_-]*|appsettings[^/]*\.json|application[^/]*\.(properties|ya?ml)|config/[^/]+\.(json|ya?ml|toml))$|^config\.(json|ya?ml|toml)$",
    )
    .expect("valid regex")
});
// The TS pattern ends in the lookahead `(?![a-z0-9-])`; the `regex` crate has none, so the match consumes the
// next character instead (anything but `[a-z0-9-]`, or the end). The match's own end is unchanged, and a
// consumed character cannot start another hostname: the only candidate, `.`, would have been part of this one.
static SERVICE_HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)[a-z0-9.-]+\.(supabase\.co|neon\.tech|psdb\.cloud|mongodb\.net|upstash\.io|turso\.io|vercel\.app|netlify\.app|fly\.dev|onrender\.com|herokuapp\.com|railway\.app|up\.railway\.app|workers\.dev|pages\.dev|digitaloceanspaces\.com|r2\.cloudflarestorage\.com|amazonaws\.com|azurewebsites\.net|run\.app|appspot\.com|firebaseio\.com)(?:[^a-z0-9-]|$)",
    )
    .expect("valid regex")
});
static YAML_ENVIRONMENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\s*)(?:-\s+)?environment:\s*(#.*)?$").expect("valid regex"));
static YAML_ENV: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\s*)(?:-\s+)?env:\s*(#.*)?$").expect("valid regex"));

fn base_of(path: &str) -> &str {
    path.rsplit_once('/').map_or(path, |(_, base)| base)
}

fn dir_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

fn env_file(path: &str) -> bool {
    is_env_file(path) || re!(r"(^|/)(\.envrc|[A-Za-z0-9_.-]+\.env)$").is_match(path) && !re!(r"(?i)(example|sample|template|dist)").is_match(base_of(path))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `text.split(/\r?\n/)`.
fn split_lines(text: &str) -> Vec<&str> {
    let mut lines: Vec<&str> = text.split('\n').collect();
    let last = lines.len() - 1;
    for line in &mut lines[..last] {
        *line = line.strip_suffix('\r').unwrap_or(line);
    }
    lines
}

/// Leading whitespace characters.
fn indent_of(line: &str) -> usize {
    line.chars().take_while(|c| c.is_whitespace()).count()
}

/// Direct children of YAML `environment:`/`env:` blocks (`head` matches the block's opening line), in map
/// (`NAME: x`) or list (`- NAME=x`) form.
fn yaml_env_keys(text: &str, head: &Regex) -> Vec<String> {
    let lines = split_lines(text);
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let Some(captures) = head.captures(line) else { continue };
        let head_indent = captures[1].chars().count();
        let mut child: Option<usize> = None;
        for next in &lines[i + 1..] {
            let trimmed = next.trim_start();
            if next.trim().is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let indent = indent_of(next);
            let list_item = trimmed.strip_prefix('-').is_some_and(|rest| rest.chars().next().is_some_and(char::is_whitespace));
            if indent <= head_indent && !(indent == head_indent && child.is_none() && list_item) {
                break;
            }
            let child = *child.get_or_insert(indent);
            if indent != child {
                continue;
            }
            if let Some(name) = re!(r#"^\s*(?:-\s*)?["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*(?:[:=]|$)"#).captures(next) {
                out.push(name[1].to_string());
            }
        }
    }
    out
}

/// A compose line as a `NAME=value` entry: `KEY: value` and `- KEY=value` become `KEY=value`.
///
/// The TS replaces `^["']?(NAME)["']?\s*:\s+(?![|>&*{[])` with `NAME=`, so a value starting a block scalar,
/// anchor, alias or flow collection is left alone. The lookahead is done in code, with the same backtracking:
/// when the first non-space character is one of those, the match still succeeds if there were two or more
/// spaces (`\s+` gives one back, and the lookahead then sees a space).
fn compose_entry(line: &str) -> String {
    let stripped = line.trim_start();
    let stripped = stripped.strip_prefix('-').unwrap_or(stripped).trim_start();
    let Some(captures) = re!(r#"^["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*:(\s+)"#).captures(stripped) else {
        return stripped.to_string();
    };
    let (Some(name), Some(spaces)) = (captures.get(1), captures.get(2)) else { return stripped.to_string() };
    let rest = &stripped[spaces.end()..];
    let blocked = rest.chars().next().is_some_and(|c| matches!(c, '|' | '>' | '&' | '*' | '{' | '['));
    let consumed = if !blocked {
        spaces.end()
    } else if spaces.as_str().chars().count() >= 2 {
        // Give back the last whitespace character.
        spaces.end() - spaces.as_str().chars().next_back().map_or(0, char::len_utf8)
    } else {
        return stripped.to_string();
    };
    format!("{}={}", name.as_str(), &stripped[consumed..])
}

/// What a fetched file holds, as names, versions and fingerprints: the text itself is dropped here.
fn read_blob(path: &str, text: &str, siblings: &[String], gitleaks_ok: bool) -> Blob {
    let mut blob = Blob { scanned: gitleaks_ok, ..Blob::default() };
    blob.images = image_references(path, text);
    if is_repo_file(path) {
        blob.findings = Some(parse_repo_file(path, text, siblings));
    }
    let mut signals: IndexMap<String, BlobSignal> = IndexMap::new();
    let mut signal = |kind: BlobSignalKind, value: &str| {
        let key = format!("{}\0{value}", if kind == BlobSignalKind::Env { "env" } else { "hostname" });
        signals.insert(key, BlobSignal { kind, value: value.to_string() });
    };
    let compose = COMPOSE.is_match(path);
    if ENV_EXAMPLE.is_match(path) {
        for m in re!(r"(?m)^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=").captures_iter(text) {
            signal(BlobSignalKind::Env, &m[1]);
        }
    }
    if compose {
        for name in yaml_env_keys(text, &YAML_ENVIRONMENT) {
            signal(BlobSignalKind::Env, &name);
        }
    }
    if WORKFLOW.is_match(path) {
        for m in re!(r"(?-u:\b)secrets\.([A-Za-z_][A-Za-z0-9_]*)").captures_iter(text) {
            signal(BlobSignalKind::Env, &m[1]);
        }
        for name in yaml_env_keys(text, &YAML_ENV) {
            signal(BlobSignalKind::Env, &name);
        }
    }
    // Lockfiles name registries, not the services the repo uses.
    if !LOCKFILES.contains(&base_of(path)) {
        for m in SERVICE_HOST.captures_iter(text) {
            let lower = m[1].to_lowercase();
            let parts: Vec<&str> = lower.split('.').collect();
            signal(BlobSignalKind::Hostname, &parts[parts.len().saturating_sub(2)..].join("."));
        }
    }
    if !signals.is_empty() {
        blob.signals = Some(signals.into_values().collect());
    }

    let mut hits: Vec<Hit> = Vec::new();
    // Env files, and literal values in compose `environment:` (`KEY: value`, `- KEY=value`), which gitleaks'
    // entropy-based generic rule misses for plain passwords.
    if env_file(path) || compose {
        for (i, line) in split_lines(text).into_iter().enumerate() {
            if line.trim_start().starts_with('#') {
                continue;
            }
            let entry = if compose { compose_entry(line) } else { re!(r"^\s*export\s+").replace(line, "").into_owned() };
            for s in env_secrets(&[entry]) {
                hits.push(Hit {
                    kind: if compose { "env-var" } else { "env-file" }.to_string(),
                    line: Some(i as u32 + 1),
                    name: Some(s.name),
                    fingerprint: Some(s.fingerprint),
                });
            }
        }
    }
    if gitleaks_ok {
        match scan_text(text) {
            Ok(found) => {
                for hit in found {
                    if !hits.iter().any(|h| h.fingerprint.as_deref() == Some(hit.fingerprint.as_str())) {
                        hits.push(Hit { kind: hit.rule, line: hit.line, name: hit.name, fingerprint: Some(hit.fingerprint) });
                    }
                }
            }
            Err(_) => blob.scanned = false,
        }
    }
    if !hits.is_empty() {
        blob.secrets = Some(hits);
    }
    blob
}

/// JS `encodeURIComponent`.
fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `new URL(url).origin` for http(s) URLs: scheme and host lower-cased, a default port dropped.
fn origin_of(url: &str) -> Result<String> {
    let (scheme, rest) = url.split_once("://").ok_or_else(|| anyhow!("Invalid URL: {url}"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("").to_lowercase();
    let scheme = scheme.to_lowercase();
    if host.is_empty() || !matches!(scheme.as_str(), "http" | "https") {
        bail!("Invalid URL: {url}");
    }
    let default_port = if scheme == "https" { ":443" } else { ":80" };
    Ok(format!("{scheme}://{}", host.strip_suffix(default_port).unwrap_or(&host)))
}

/// Contents of a blob response.
#[derive(Deserialize)]
struct BlobBody {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    encoding: Option<String>,
}

#[derive(Deserialize)]
struct TreeBody {
    #[serde(default)]
    tree: Option<Vec<TreeEntry>>,
    #[serde(default)]
    truncated: bool,
}

#[derive(Deserialize)]
struct SecretsBody {
    #[serde(default)]
    secrets: Option<Vec<SecretName>>,
}

#[derive(Deserialize)]
struct SecretName {
    name: String,
}

#[derive(Deserialize)]
struct Deployment {
    #[serde(default)]
    creator: Option<Creator>,
    #[serde(default)]
    environment: Option<String>,
}

#[derive(Deserialize)]
struct Creator {
    #[serde(default)]
    login: Option<String>,
}

/// GitHub's API, as the one configured origin the token may go to.
struct Client<'a> {
    config: &'a GithubCollector,
    fetch: &'a dyn Fetch,
    origin: String,
}

fn http_error(path: &str, res: &Response) -> anyhow::Error {
    anyhow!("GET {}: HTTP {}", path.split('?').next().unwrap_or(path), res.status)
}

impl<'a> Client<'a> {
    fn new(config: &'a GithubCollector, context: &CollectContext<'a>) -> Result<Self> {
        Ok(Self { config, fetch: context.fetch, origin: origin_of(&config.api_url)? })
    }

    fn get(&self, path_or_url: &str) -> Result<Response> {
        let url = if path_or_url.starts_with('/') { format!("{}{path_or_url}", self.config.api_url) } else { path_or_url.to_string() };
        // Pagination links come from the response: the token only ever goes to the configured API.
        let origin = origin_of(&url)?;
        if origin != self.origin {
            bail!("refusing to send the GitHub token to {origin}");
        }
        let request = Request::get(url)
            .header("Authorization", format!("Bearer {}", self.config.token))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", USER_AGENT);
        let res = self.fetch.fetch(request)?;
        if (res.status == 403 || res.status == 429)
            && (res.status == 429 || res.header("x-ratelimit-remaining") == Some("0") || res.header("retry-after").is_some())
        {
            let reset = res
                .header("x-ratelimit-reset")
                .and_then(|v| v.trim().parse::<f64>().ok())
                .filter(|v| v.is_finite() && *v != 0.0)
                .and_then(|v| jiff::Timestamp::from_millisecond((v * 1000.0) as i64).ok());
            return Err(
                RateLimited(format!("GitHub API rate limit reached{}", reset.map_or(String::new(), |ts| format!(" (resets {})", util::iso(ts))))).into()
            );
        }
        Ok(res)
    }

    fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let res = self.get(path)?;
        if !res.ok() {
            return Err(http_error(path, &res));
        }
        res.json()
    }
}

/// What one collection shares between the repo workers.
struct Refresh<'a> {
    client: &'a Client<'a>,
    config: &'a GithubCollector,
    cache: &'a Cache,
    next: Mutex<Cache>,
    gitleaks_ok: bool,
}

impl Refresh<'_> {
    /// A repo's entry, as it was, goes into the new cache with the blobs it names.
    fn keep(&self, full: &str, entry: RepoEntry) {
        let mut next = lock(&self.next);
        for key in entry.files.values() {
            if let Some(blob) = self.cache.blobs.get(key)
                && !next.blobs.contains_key(key)
            {
                next.blobs.insert(key.clone(), blob.clone());
            }
        }
        next.repos.insert(full.to_string(), entry);
    }

    fn refresh(&self, repo: &Repo) -> Result<RepoEntry> {
        let full = repo.full_name.as_str();
        let mut entry = RepoEntry { pushed_at: repo.pushed_at.clone().unwrap_or_default(), scanned: self.gitleaks_ok, ..RepoEntry::default() };
        let mut tree: Vec<TreeEntry> = Vec::new();
        if let Some(branch) = repo.default_branch.as_deref().filter(|b| !b.is_empty()) {
            let encoded: Vec<String> = branch.split('/').map(encode_uri_component).collect();
            let path = format!("/repos/{full}/git/trees/{}?recursive=1", encoded.join("/"));
            let res = self.client.get(&path)?;
            // 404/409: an empty repo.
            if res.ok() {
                let body: TreeBody = res.json()?;
                tree = body.tree.unwrap_or_default().into_iter().filter(|file| file.r#type == "blob").collect();
                if body.truncated {
                    entry.warnings.push(format!("{full}: GitHub truncated the file tree; files beyond it were not read"));
                }
            } else if res.status != 404 && res.status != 409 {
                return Err(http_error(&path, &res));
            }
        }
        let mut by_dir: HashMap<&str, Vec<String>> = HashMap::new();
        for file in &tree {
            by_dir.entry(dir_of(&file.path)).or_default().push(file.path.clone());
        }
        for file in &tree {
            let path = file.path.as_str();
            if env_file(path) {
                entry.env_files.push(path.to_string());
            }
            if vendor_file_match(path) {
                entry.vendor_files.push(path.to_string());
            }
            let manifest = is_repo_file(path);
            if !manifest
                && (is_vendored(path)
                    || !(env_file(path) || ENV_EXAMPLE.is_match(path) || WORKFLOW.is_match(path) || COMPOSE.is_match(path) || SECRET_FILE.is_match(path)))
            {
                continue;
            }
            let cap = if manifest { self.config.max_file_bytes } else { (SMALL as u64).min(self.config.max_file_bytes) };
            let size = file.size.unwrap_or(0);
            if size > cap {
                entry.warnings.push(format!("{full}: {path} is {size} bytes, over the {cap}-byte limit: not read"));
                continue;
            }
            // Parsing depends on the path and its directory (a lockfile beside a package.json), so both are in the key.
            let siblings: &[String] = by_dir.get(dir_of(path)).map_or(&[], Vec::as_slice);
            let mut names: Vec<&str> = siblings.iter().map(|s| base_of(s)).collect();
            names.sort_unstable();
            let mut parts = vec![path];
            parts.extend(names);
            let key = format!("{}:{}", file.sha, &util::sha256_hex(parts.join("\0").as_bytes())[..12]);
            let cached = {
                let next = lock(&self.next);
                next.blobs.get(&key).or_else(|| self.cache.blobs.get(&key)).cloned()
            };
            let blob = match cached {
                Some(blob) if (blob.scanned || !self.gitleaks_ok) && (blob.images.is_some() || !names_images(path)) => blob,
                _ => {
                    let body: BlobBody = self.client.get_json(&format!("/repos/{full}/git/blobs/{}", file.sha))?;
                    let content = body.content.unwrap_or_default();
                    let text = if body.encoding.as_deref() == Some("base64") {
                        // Node's Buffer decoder skips what is not base64 instead of failing.
                        let clean: String = content.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/')).collect();
                        String::from_utf8_lossy(&util::base64_decode(&clean)?).into_owned()
                    } else {
                        content
                    };
                    read_blob(path, &text, siblings, self.gitleaks_ok)
                }
            };
            if !blob.scanned {
                entry.scanned = false;
            }
            lock(&self.next).blobs.insert(key.clone(), blob);
            entry.files.insert(path.to_string(), key);
        }
        // Both need more than Contents/Metadata read; without it they are skipped silently.
        let secrets = self.client.get(&format!("/repos/{full}/actions/secrets?per_page=100"))?;
        if secrets.ok() {
            let body: SecretsBody = secrets.json()?;
            entry.actions = body.secrets.unwrap_or_default().into_iter().map(|s| s.name).collect();
        }
        let deployments = self.client.get(&format!("/repos/{full}/deployments?per_page=30"))?;
        if deployments.ok() {
            let list: Vec<Deployment> = deployments.json()?;
            for d in list {
                for value in [d.creator.and_then(|c| c.login), d.environment].into_iter().flatten().filter(|v| !v.is_empty()) {
                    if !entry.deployments.contains(&value) {
                        entry.deployments.push(value);
                    }
                }
            }
        }
        Ok(entry)
    }
}

fn finding(config: &GithubCollector, where_: &str, location: &str, hit: &Hit, exposure: Exposure, risk: &str) -> SecretFinding {
    SecretFinding {
        host: config.name.clone(),
        r#where: where_.to_string(),
        location: location.to_string(),
        line: hit.line.filter(|l| *l != 0),
        commit: None,
        kind: hit.kind.clone(),
        name: hit.name.clone().filter(|n| !n.is_empty()),
        fingerprint: hit.fingerprint.clone().filter(|f| !f.is_empty()),
        exposure,
        risk: risk.to_string(),
        providers: providers_of(&hit.kind, hit.name.as_deref()),
        collector: None,
    }
}

/// Registry lookups of image env per collection.
pub const MAX_IMAGE_LOOKUPS: usize = 40;
/// How long a registry's answer for an image reference is kept, in seconds.
const IMAGE_ENV_TTL: i64 = 24 * 60 * 60;

/// What to ask a registry for: the reference without its digest. Not an image a registry can answer for: `scratch`, and a
/// digest with no tag (the tag the registry would use may have moved on since the digest was pinned).
fn registry_reference(reference: &str) -> Option<String> {
    let (name, digest) = reference.split_once('@').map_or((reference, false), |(name, _)| (name, true));
    let name = name.trim();
    let tagged = name.rfind(':').is_some_and(|colon| name.rfind('/').is_none_or(|slash| colon > slash));
    if name.is_empty() || name == "scratch" || (digest && !tagged) { None } else { Some(name.to_string()) }
}

/// Every Dockerfile and compose file of the repo, as last read, names its images in a cached blob.
fn images_recorded(entry: &RepoEntry, cache: &Cache) -> bool {
    entry.files.iter().all(|(path, key)| !names_images(path) || cache.blobs.get(key).is_none_or(|blob| blob.images.is_some()))
}

/// The env of every image the collected repos name, into `next.images`: from `old` (the previous cache) when read less than 24 hours ago and from
/// its registry otherwise: oldest answers first, at most `MAX_IMAGE_LOOKUPS` per collection. A registry that cannot
/// answer is a warning (its failure is kept for the same 24 hours), never a collector failure.
fn read_images(
    config: &GithubCollector,
    context: &CollectContext,
    repos: &[Repo],
    old: &IndexMap<String, ImageEnv>,
    next: &mut Cache,
    now: Timestamp,
    warnings: &mut Vec<String>,
) {
    let mut wanted: IndexSet<String> = IndexSet::new();
    for repo in repos {
        let Some(entry) = next.repos.get(&repo.full_name) else { continue };
        for key in entry.files.values() {
            wanted.extend(next.blobs.get(key).and_then(|blob| blob.images.as_ref()).into_iter().flatten().filter_map(|image| registry_reference(image)));
        }
    }
    let mut stale: Vec<&String> = Vec::new();
    for image in &wanted {
        match old.get(image) {
            Some(read) if util::parse_time(&read.at).is_some_and(|at| (0..IMAGE_ENV_TTL).contains(&(now.as_second() - at.as_second()))) => {
                next.images.insert(image.clone(), read.clone());
            }
            _ => stale.push(image),
        }
    }
    // Never read first, then the longest ago: with more than the cap, every image is read in turn.
    stale.sort_by_cached_key(|image| old.get(*image).map(|read| read.at.clone()).unwrap_or_default());
    let (lookups, skipped) = stale.split_at(stale.len().min(MAX_IMAGE_LOOKUPS));
    let results = util::parallel_map(lookups, CONCURRENCY, |image| image_env(image, context.fetch));
    for (image, result) in lookups.iter().zip(results) {
        let at = util::iso(now);
        let read = match result {
            Ok(env) => ImageEnv { at, env: kept_env(Some(env.as_slice())).into_iter().map(str::to_string).collect(), error: None },
            Err(error) => ImageEnv { at, env: Vec::new(), error: Some(error.to_string()) },
        };
        next.images.insert((*image).clone(), read);
    }
    for image in skipped {
        if let Some(read) = old.get(*image) {
            next.images.insert((*image).clone(), read.clone());
        }
    }
    if !skipped.is_empty() {
        warnings.push(format!(
            "{}: {} images not read: at most {MAX_IMAGE_LOOKUPS} registry lookups per collection, the rest are read in the next ones",
            config.name,
            skipped.len()
        ));
    }
    for image in &wanted {
        if let Some(error) = next.images.get(image).and_then(|read| read.error.as_ref()) {
            warnings.push(format!("{image}: image env not read: {error}"));
        }
    }
}

fn item_kind(kind: RepoFindingKind) -> ItemKind {
    match kind {
        RepoFindingKind::Package => ItemKind::Package,
        RepoFindingKind::Runtime => ItemKind::Runtime,
        RepoFindingKind::Image => ItemKind::Image,
        RepoFindingKind::Os => ItemKind::Os,
        RepoFindingKind::Platform => ItemKind::Platform,
    }
}

pub fn collect_github(config: &GithubCollector, context: &CollectContext) -> Result<Collected> {
    let cache_name = format!("{}.cache.json", config.name);
    let cache: Cache = read_state(context.state_dir, &cache_name).unwrap_or_default();
    let mut warnings: Vec<String> = Vec::new();
    let gitleaks_ok = gitleaks_available();
    if !gitleaks_ok {
        warnings.push("gitleaks is not installed: repo files not scanned for secrets (https://github.com/gitleaks/gitleaks, MIT)".to_string());
    }
    let client = Client::new(config, context)?;

    // The repos: all the token reads, narrowed by the config. Explicit names outside that list are fetched one by one.
    let mut listed: Vec<Repo> = Vec::new();
    let mut page = Some("/user/repos?per_page=100&affiliation=owner,collaborator,organization_member".to_string());
    while let Some(current) = page {
        let res = client.get(&current)?;
        if !res.ok() {
            return Err(http_error("/user/repos", &res));
        }
        listed.extend(res.json::<Vec<Repo>>()?);
        page = re!(r#"<([^>]+)>;\s*rel="next""#).captures(res.header("link").unwrap_or("")).map(|c| c[1].to_string());
    }
    let explicit: Vec<&String> = config.repos.iter().filter(|pattern| !pattern.contains(['*', '?'])).collect();
    let named = |full: &str| explicit.iter().any(|name| name.to_lowercase() == full.to_lowercase());
    let wanted = |repo: &Repo| {
        (config.repos.is_empty() || config.repos.iter().any(|pattern| glob_match(pattern, &repo.full_name)))
            && !config.exclude.iter().any(|pattern| glob_match(pattern, &repo.full_name))
            && (named(&repo.full_name) || (config.include_forks || !repo.fork) && (config.include_archived || !repo.archived))
    };
    let mut repos: Vec<Repo> = listed.iter().filter(|repo| wanted(repo)).cloned().collect();
    for name in &explicit {
        if listed.iter().any(|repo| repo.full_name.to_lowercase() == name.to_lowercase()) {
            continue;
        }
        if !re!(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$").is_match(name) {
            warnings.push(format!("{name}: not an owner/name repo"));
            continue;
        }
        let res = client.get(&format!("/repos/{name}"))?;
        if res.ok() {
            let repo: Repo = res.json()?;
            if wanted(&repo) {
                repos.push(repo);
            }
        } else {
            warnings.push(format!("{name}: not found or not readable with this token (HTTP {})", res.status));
        }
    }

    let shared = Refresh { client: &client, config, cache: &cache, next: Mutex::new(Cache::default()), gitleaks_ok };
    let queue: Mutex<VecDeque<Repo>> = Mutex::new(repos.iter().cloned().collect());
    let limited: Mutex<Option<String>> = Mutex::new(None);
    let cut = AtomicUsize::new(0);
    let failures: Mutex<Vec<String>> = Mutex::new(Vec::new());
    util::parallel_map(&[(); CONCURRENCY], CONCURRENCY, |_| {
        loop {
            if lock(&limited).is_some() {
                break;
            }
            let Some(repo) = lock(&queue).pop_front() else { break };
            let full = repo.full_name.as_str();
            let prev = cache.repos.get(full);
            if let Some(prev) = prev
                && prev.pushed_at == repo.pushed_at.as_deref().unwrap_or("")
                && (prev.scanned || !gitleaks_ok)
                && images_recorded(prev, &cache)
            {
                shared.keep(full, prev.clone());
                continue;
            }
            match shared.refresh(&repo) {
                Ok(entry) => shared.keep(full, entry),
                Err(error) => {
                    if let Some(rate) = error.downcast_ref::<RateLimited>() {
                        *lock(&limited) = Some(rate.0.clone());
                        cut.fetch_add(1, Ordering::SeqCst);
                    } else {
                        lock(&failures).push(format!("{full}: {error}"));
                    }
                    if let Some(prev) = prev {
                        shared.keep(full, prev.clone());
                    }
                }
            }
        }
    });
    warnings.extend(failures.into_inner().unwrap_or_else(PoisonError::into_inner));
    let limited = limited.into_inner().unwrap_or_else(PoisonError::into_inner);
    let queue = queue.into_inner().unwrap_or_else(PoisonError::into_inner);
    let mut next = shared.next.into_inner().unwrap_or_else(PoisonError::into_inner);
    if let Some(limited) = limited {
        // Repos the limit cut off keep what the last refresh saw.
        for repo in &queue {
            if let Some(prev) = cache.repos.get(&repo.full_name) {
                for key in prev.files.values() {
                    if let Some(blob) = cache.blobs.get(key) {
                        next.blobs.entry(key.clone()).or_insert_with(|| blob.clone());
                    }
                }
                next.repos.insert(repo.full_name.clone(), prev.clone());
            }
        }
        if next.repos.is_empty() {
            bail!("{limited}: no repos collected");
        }
        warnings.push(format!("{limited}: {} repos not refreshed, their previous results kept", queue.len() + cut.load(Ordering::SeqCst)));
    }
    read_images(config, context, &repos, &cache.images, &mut next, util::now(), &mut warnings);
    write_state(context.state_dir, &cache_name, &next)?;

    let mut items: Vec<InventoryItem> = Vec::new();
    let mut secrets: Vec<SecretFinding> = Vec::new();
    let mut signals: Vec<VendorSignal> = Vec::new();
    for repo in &repos {
        let Some(entry) = next.repos.get(&repo.full_name) else { continue };
        let where_ = format!("repo:{}", repo.full_name);
        let audience = if repo.private {
            "a private repo: everyone with read access, every fork and its CI can read it"
        } else {
            "a public repo: anyone on the internet can read it"
        };
        let env_risk = format!("Env file committed to {audience}; deleting it does not remove it from git history: rotate what it holds");
        let mut seen: std::collections::HashSet<(u8, String, String)> = std::collections::HashSet::new();
        let mut signal = |signals: &mut Vec<VendorSignal>, kind: VendorSignalKind, value: &str, path: &str| {
            if seen.insert((kind as u8, value.to_string(), path.to_string())) {
                signals.push(VendorSignal {
                    host: config.name.clone(),
                    r#where: where_.clone(),
                    kind,
                    value: value.to_string(),
                    path: Some(path.to_string()),
                    collector: None,
                });
            }
        };
        let mut from_images: Vec<InventoryItem> = Vec::new();
        for (path, key) in &entry.files {
            let Some(blob) = next.blobs.get(key) else { continue };
            for f in blob.findings.iter().flatten() {
                items.push(InventoryItem {
                    host: config.name.clone(),
                    r#where: where_.clone(),
                    kind: item_kind(f.kind),
                    ecosystem: f.ecosystem.clone(),
                    name: f.name.clone(),
                    version: f.version.clone(),
                    path: Some(path.clone()),
                    running: None,
                    dev: f.dev,
                    collector: None,
                });
            }
            // What the images this file names declare in their env (the server inside a bundling image).
            let references: IndexSet<String> = blob.images.iter().flatten().filter_map(|image| registry_reference(image)).collect();
            for reference in &references {
                let Some(read) = next.images.get(reference).filter(|read| read.error.is_none()) else { continue };
                for mut item in env_runtimes(read.env.iter().map(String::as_str), Base::new(&config.name, &where_)) {
                    item.path = Some(path.clone());
                    from_images.push(item);
                }
            }
            for s in blob.signals.iter().flatten() {
                let kind = if s.kind == BlobSignalKind::Env { VendorSignalKind::Env } else { VendorSignalKind::Hostname };
                signal(&mut signals, kind, &s.value, path);
            }
            let env = entry.env_files.contains(path);
            for hit in blob.secrets.iter().flatten() {
                secrets.push(if env {
                    finding(config, &where_, path, hit, Exposure::CommittedEnvFile, &env_risk)
                } else {
                    finding(
                        config,
                        &where_,
                        path,
                        hit,
                        Exposure::RepoFile,
                        &format!("Committed in {path} on the default branch of {audience}; deleting it does not remove it from git history: rotate it"),
                    )
                });
            }
        }
        items.extend(dedupe(from_images));
        for path in &entry.env_files {
            if !secrets.iter().any(|s| s.r#where == where_ && s.location == *path) {
                let hit = Hit { kind: "env-file".to_string(), line: None, name: None, fingerprint: None };
                secrets.push(finding(config, &where_, path, &hit, Exposure::CommittedEnvFile, &env_risk));
            }
        }
        for name in &entry.actions {
            let hit = Hit { kind: "actions-secret".to_string(), line: None, name: Some(name.clone()), fingerprint: None };
            secrets.push(finding(
                config,
                &where_,
                "actions",
                &hit,
                Exposure::CiSecret,
                "GitHub Actions secret: any workflow in the repo can read it, so anyone who can push a workflow can exfiltrate it; rotate if the repo or its CI is compromised",
            ));
            signal(&mut signals, VendorSignalKind::Env, name, "actions");
        }
        for path in &entry.vendor_files {
            signal(&mut signals, VendorSignalKind::File, path, path);
        }
        for value in &entry.deployments {
            signal(&mut signals, VendorSignalKind::Deployment, value, "deployments");
        }
        warnings.extend(entry.warnings.iter().cloned());
    }
    (context.log)(&format!("{}: {} repos, {} items, {} secrets", config.name, repos.len(), items.len(), secrets.len()));
    Ok(Collected { items, services: Vec::new(), secrets, signals, warnings })
}
