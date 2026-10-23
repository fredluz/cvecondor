// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! One config file switches everything on: the inventory collectors, the
//! classifier, the responder and the notifiers. Secrets are `${ENV_VAR}`
//! references, resolved at load time and remembered, so logs can redact them
//! and the responder never inherits them.

use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Result, anyhow, bail};
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::name::{ENV_PREFIX, NAME};
use crate::vendors::catalog::{VendorFeed, VendorFeedKind};

/// The process environment, passed explicitly so tests can pass their own.
pub type Env = HashMap<String, String>;

pub fn process_env() -> Env {
    std::env::vars_os().filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?))).collect()
}

/// Per case. `Act`: every place it touches is listed in `responder.actOn` (update, work around, last-resort stop).
/// `Update`: a fixed release exists and `responder.updateWhenFixed` is on: apply the update, nothing else.
/// `Propose`: everything else; the responder runs nothing and writes the exact steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Propose,
    Update,
    Act,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Propose => "propose",
            Self::Update => "update",
            Self::Act => "act",
        }
    }
}

/// Whether "a fix exists → just update" runs without a per-service opt-in. The one line to flip the default.
pub const DEFAULT_UPDATE_WHEN_FIXED: bool = true;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Agent {
    Claude,
    Codex,
    Omp,
}

impl Agent {
    pub const NAMES: &'static str = "claude, codex, omp";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Omp => "omp",
        }
    }

    /// The preset a name stands for.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "claude" => Some(Self::Claude),
            "codex" => Some(Self::Codex),
            "omp" => Some(Self::Omp),
            _ => None,
        }
    }
}

/// What a notice is about. `Urgent`: one short line, for what can't wait (exploitable now, a
/// workaround or stop under way); the rest is for the agent in charge to summarise. `Test` reaches
/// every notifier and is never accepted in config (`NOTIFY_EVENTS` leaves it out).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NotifyEvent {
    Urgent,
    Case,
    Report,
    Secrets,
    Test,
}

/// The events a notifier may list in `events`, in the order the error message names them.
pub const NOTIFY_EVENTS: [NotifyEvent; 4] = [NotifyEvent::Urgent, NotifyEvent::Case, NotifyEvent::Report, NotifyEvent::Secrets];

impl NotifyEvent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Urgent => "urgent",
            Self::Case => "case",
            Self::Report => "report",
            Self::Secrets => "secrets",
            Self::Test => "test",
        }
    }
}

// Every collector reads only. Its credentials (the GitHub token, the SSH key,
// the Docker socket) belong to the watcher and never reach the responder.
// Installed apps on people's own machines are v2: another member of this enum.

/// The user's GitHub repos: lockfiles, manifests, Dockerfile and compose base images.
#[derive(Debug, Clone)]
pub struct GithubCollector {
    pub name: String,
    /// Fine-grained token with Contents: read and Metadata: read.
    pub token: String,
    pub api_url: String,
    /// `owner/name` globs; empty: every repo the token can read.
    pub repos: Vec<String>,
    pub exclude: Vec<String>,
    pub include_forks: bool,
    pub include_archived: bool,
    pub max_file_bytes: u64,
}

/// The Linux machine the watcher runs on (or, from a container, the host mounted read-only at `root`).
#[derive(Debug, Clone)]
pub struct HostCollector {
    pub name: String,
    /// `/`, or `/host` when the container mounts the host's `/` there read-only.
    pub root: PathBuf,
    /// Extra binaries to version with `--version` (only when root is `/`).
    pub binaries: Vec<String>,
}

/// TLS files for a Docker endpoint (PEM).
#[derive(Debug, Clone, Default)]
pub struct DockerTls {
    pub ca: Option<PathBuf>,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
}

/// A Docker Engine API: containers, their images, OS packages, runtimes and exposure. GET requests only unless `exec`.
#[derive(Debug, Clone)]
pub struct DockerCollector {
    pub name: String,
    /// `unix:///var/run/docker.sock`, `tcp://host:2375`, or `https://host:2376` with `tls`.
    pub endpoint: String,
    pub tls: Option<DockerTls>,
    /// Also run `--version` probes and `pip list` inside running containers (POST /exec).
    pub exec: bool,
}

/// A remote Linux host over SSH: the host collector's reads, plus its containers through the docker CLI (inspect and cp, never exec).
#[derive(Debug, Clone)]
pub struct SshCollector {
    pub name: String,
    /// An alias from ~/.ssh/config, `host` or `user@host`.
    pub host: String,
    pub port: Option<u16>,
    pub identity_file: Option<PathBuf>,
    /// Extra `-o Key=Value` options.
    pub ssh_options: Vec<String>,
    /// Prefix privileged reads with `sudo -n`.
    pub sudo: bool,
    pub docker: bool,
    pub timeout_seconds: f64,
}

#[derive(Debug, Clone)]
pub enum CollectorConfig {
    Github(GithubCollector),
    Host(HostCollector),
    Docker(DockerCollector),
    Ssh(SshCollector),
}

impl CollectorConfig {
    pub fn name(&self) -> &str {
        match self {
            Self::Github(c) => &c.name,
            Self::Host(c) => &c.name,
            Self::Docker(c) => &c.name,
            Self::Ssh(c) => &c.name,
        }
    }

    /// The `type` string of the config file: `github`, `host`, `docker`, `ssh`.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Github(_) => "github",
            Self::Host(_) => "host",
            Self::Docker(_) => "docker",
            Self::Ssh(_) => "ssh",
        }
    }
}

/// `api_key` absent: classifier.dev's anonymous free tier, only when the config asks for it (`"anonymous": true`).
#[derive(Debug, Clone)]
pub struct ClassifierConfig {
    pub api_key: Option<String>,
    pub url: String,
    pub model: String,
    pub tier: String,
    pub timeout_seconds: f64,
}

/// The argv the responder runs for each mode. Resolved at config load: `responder.command` as one array
/// (every mode), or an object keyed by mode (a missing mode takes `act`, `update`, `propose`, whichever is
/// set first), or the preset the optional `agent` names.
///
/// Placeholders are replaced anywhere inside an argument (`@{prompt}` works): `{prompt}` (the prompt file;
/// when no argument has it, the prompt goes on stdin), `{brief}` (the standing brief: shared rules, triage and
/// the list of path files, written to the work dir as `brief.md`, so it exists even for the compiled-in brief),
/// `{case}` (the case file), `{report}` (where the report is written), `{workdir}`, `{mode}` (`propose`,
/// `update` or `act`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponderCommand {
    pub propose: Vec<String>,
    pub update: Vec<String>,
    pub act: Vec<String>,
}

impl ResponderCommand {
    /// The argv for one mode.
    pub fn for_mode(&self, mode: Mode) -> &[String] {
        match mode {
            Mode::Propose => &self.propose,
            Mode::Update => &self.update,
            Mode::Act => &self.act,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResponderConfig {
    /// A preset name (`claude`, `codex`, `omp`): a shorthand for `command`, used only when `command` is absent.
    /// With `command` set it is just a label.
    pub agent: Option<String>,
    /// What runs for each mode; see `ResponderCommand`.
    pub command: ResponderCommand,
    /// The standing brief: the shipped one unless you point at your own.
    pub brief: PathBuf,
    /// Appended to the brief: your environment, your rules (who to tell, what never to touch).
    pub notes: Option<String>,
    /// The per-service opt-in to act: repos (`owner/name`), containers, systemd units or hostnames (globs; `*` = all).
    /// On these the responder patches, mitigates (guard, disable, block, pin), opens fix PRs, and as a last resort stops
    /// the service, restorably. Everywhere else it proposes the same steps and runs none. Empty (default): propose only.
    pub act_on: Vec<String>,
    /// A fixed release exists → apply it, batched per host and repo, without a per-service opt-in. Default: `DEFAULT_UPDATE_WHEN_FIXED` (on).
    pub update_when_fixed: bool,
    /// Services (same globs as `act_on`) where fixes are proposed, never applied automatically.
    pub update_except: Vec<String>,
    pub max_per_cycle: f64,
    pub timeout_minutes: f64,
    pub cwd: Option<PathBuf>,
    pub env: IndexMap<String, String>,
    /// Shell commands the responder runs itself to put an urgent line in front of the user (the line on stdin), besides
    /// the watcher's notifiers: a chat their agent reads, a messaging bridge. Set at setup. Claude's `propose` preset
    /// allows exactly these (`Bash(<command>:*)`) and no other shell.
    pub reach: Vec<String>,
}

/// A vendor the user names by hand (accounts used outside code), or extra feeds for a catalogue vendor.
#[derive(Debug, Clone, PartialEq)]
pub struct VendorConfig {
    pub id: String,
    pub name: Option<String>,
    pub aliases: Vec<String>,
    pub feeds: Vec<VendorFeed>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailSecurity {
    Tls,
    Starttls,
    None,
}

impl EmailSecurity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Starttls => "starttls",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone)]
pub enum NotifierKind {
    /// `replies`: the watcher also reads this bot's messages (`getUpdates`) from `chat_id` and has the agent in charge
    /// (the responder's `act` command) answer them; see `relay`. The bot must be CVECondor's own: it is the only reader.
    Telegram {
        bot_token: String,
        chat_id: String,
        replies: bool,
    },
    Slack {
        webhook_url: String,
    },
    Webhook {
        url: String,
        headers: IndexMap<String, String>,
    },
    Email {
        host: String,
        port: u16,
        security: EmailSecurity,
        user: Option<String>,
        pass: Option<String>,
        from: String,
        to: Vec<String>,
    },
    Command {
        command: Vec<String>,
    },
}

/// One notifier: which events it gets, and how it delivers them.
#[derive(Debug, Clone)]
pub struct NotifierConfig {
    pub events: Vec<NotifyEvent>,
    pub kind: NotifierKind,
}

impl NotifierConfig {
    /// The `type` string of the config file: `telegram`, `slack`, `webhook`, `email`, `command`.
    pub fn type_name(&self) -> &'static str {
        match self.kind {
            NotifierKind::Telegram { .. } => "telegram",
            NotifierKind::Slack { .. } => "slack",
            NotifierKind::Webhook { .. } => "webhook",
            NotifierKind::Email { .. } => "email",
            NotifierKind::Command { .. } => "command",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub file: PathBuf,
    pub state_dir: PathBuf,
    pub poll_minutes: f64,
    pub inventory_hours: f64,
    /// IANA zone for report dates.
    pub timezone: String,
    /// Repos (`owner/name`), containers and hostnames (globs) that serve your customers or matter most; they lead every case and message.
    pub priority: Vec<String>,
    pub disabled_sources: Vec<String>,
    /// General security news (Hacker News front page, BleepingComputer, The Hacker News, SecurityWeek, Krebs), matched against your vendors.
    pub news: bool,
    pub collectors: Vec<CollectorConfig>,
    /// Vendors added by hand; detected ones come from the inventory at runtime.
    pub vendors: Vec<VendorConfig>,
    /// Catalogue vendor ids never to watch even when detected.
    pub ignore_vendors: Vec<String>,
    /// `{ "KEY_NAME": [{ "place": "vercel:acme-web (production)", "vendor": "vercel" }] }`, built at install: every place each key is stored. Names only.
    pub rotation_map: Option<PathBuf>,
    /// Directory of per-service runbooks (`<service>.md`: stop, bring back, rotate, redeploy) written at install; matched ones go into case files.
    pub runbooks: Option<PathBuf>,
    pub classifier: Option<ClassifierConfig>,
    pub responder: Option<ResponderConfig>,
    pub notify: Vec<NotifierConfig>,
    /// Resolved secret values, for redaction.
    pub secrets: Vec<String>,
    /// Environment variables the config reads; kept out of the responder's environment.
    pub secret_env: Vec<String>,
}

/// The responder's brief files, compiled in: a lone binary still has them.
pub const SHIPPED_BRIEF_FILES: &[(&str, &str)] = &[
    ("common.md", include_str!("../agent/respond/common.md")),
    ("triage.md", include_str!("../agent/respond/triage.md")),
    ("update.md", include_str!("../agent/respond/update.md")),
    ("not-exploitable.md", include_str!("../agent/respond/not-exploitable.md")),
    ("workaround.md", include_str!("../agent/respond/workaround.md")),
    ("shutdown.md", include_str!("../agent/respond/shutdown.md")),
    ("propose.md", include_str!("../agent/respond/propose.md")),
    ("breach.md", include_str!("../agent/respond/breach.md")),
    ("distrust.md", include_str!("../agent/respond/distrust.md")),
];

/// The shipped brief directory: next to an installed binary (`<exe dir>/../share/cvecondor/respond`, or
/// `<exe dir>/agent/respond`), in `/usr/share/cvecondor/respond`, or in the source tree the binary was built
/// from; the first that exists. When none does, the source-tree path (`read_brief` then serves the compiled-in files).
pub fn shipped_brief() -> PathBuf {
    let mut candidates = Vec::new();
    if let Some(dir) = std::env::current_exe().ok().and_then(|exe| exe.parent().map(Path::to_path_buf)) {
        candidates.push(resolve(&dir.join("..").join("share").join(NAME).join("respond")));
        candidates.push(dir.join("agent").join("respond"));
    }
    candidates.push(Path::new("/usr/share").join(NAME).join("respond"));
    let source_tree = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/agent/respond"));
    candidates.push(source_tree.clone());
    candidates.into_iter().find(|p| p.join("common.md").exists()).unwrap_or(source_tree)
}

/// Reads one file of a brief directory (`common.md`, `triage.md`, `<path>.md`). The shipped brief falls back to
/// the compiled-in files when its directory is gone.
pub fn read_brief(dir: &Path, file: &str) -> Result<String> {
    let path = dir.join(file);
    match fs::read_to_string(&path) {
        Ok(text) => Ok(text),
        Err(e) => match SHIPPED_BRIEF_FILES.iter().find(|(name, _)| *name == file) {
            Some((_, text)) if dir == shipped_brief() => Ok((*text).to_string()),
            _ => Err(anyhow!("{}: {e}", path.display())),
        },
    }
}

pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME").filter(|h| !h.is_empty()).map(PathBuf::from).or_else(std::env::home_dir).unwrap_or_else(|| PathBuf::from("/"))
}

/// Node's `path.resolve` for one path: absolute (against the working directory), `.` and `..` folded, no trailing slash.
pub fn resolve(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() { path.to_path_buf() } else { std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")).join(path) };
    let mut out = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => out.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if out.parent().is_some() {
                    out.pop();
                }
            }
            Component::Normal(part) => out.push(part),
        }
    }
    out
}

pub fn expand_home(path: &str) -> String {
    if path == "~" || path.starts_with("~/") { format!("{}{}", home_dir().display(), &path[1..]) } else { path.to_string() }
}

/// `--config`, `CVECONDOR_CONFIG`, else `~/.config/cvecondor/config.json` (or `config.jsonc`).
pub fn config_path(explicit: Option<&str>, env: &Env) -> PathBuf {
    let from_env = env.get(&format!("{ENV_PREFIX}_CONFIG")).map(String::as_str);
    if let Some(chosen) = explicit.filter(|s| !s.is_empty()).or(from_env.filter(|s| !s.is_empty())) {
        return resolve(Path::new(chosen));
    }
    let dir = home_dir().join(".config").join(NAME);
    if dir.join("config.jsonc").exists() && !dir.join("config.json").exists() { dir.join("config.jsonc") } else { dir.join("config.json") }
}

static ENV_LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$").expect("valid regex"));

/// The `NAME=value` lines of a dotenv file, in order (Node's `process.loadEnvFile` reading: `export`
/// prefix, single, double and backtick quotes that may span lines, `\n` in double quotes, `#` comments).
fn parse_env_text(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < text.len() {
        let line_end = text[at..].find('\n').map_or(text.len(), |p| at + p);
        let line = text[at..line_end].trim_end_matches('\r');
        let Some(c) = ENV_LINE.captures(line) else {
            at = line_end + 1;
            continue;
        };
        let rest = c.get(2).expect("group 2 always matches");
        let value_start = at + rest.start() + (rest.as_str().len() - rest.as_str().trim_start().len());
        let value_text = &text[value_start..];
        let mut next = line_end + 1;
        let mut value = None;
        if let Some(quote) = value_text.chars().next().filter(|q| matches!(q, '"' | '\'' | '`')) {
            let body = &value_text[1..];
            let mut skip = false;
            let mut close = None;
            for (i, ch) in body.char_indices() {
                if skip {
                    skip = false;
                } else if ch == '\\' && body[i + 1..].starts_with(quote) {
                    skip = true;
                } else if ch == quote {
                    close = Some(i);
                    break;
                }
            }
            if let Some(i) = close {
                let inner = &body[..i];
                value = Some(if quote == '"' { inner.replace("\\n", "\n") } else { inner.to_string() });
                next = text[value_start + 1 + i..].find('\n').map_or(text.len(), |p| value_start + 1 + i + p) + 1;
            }
        }
        let value = value.unwrap_or_else(|| rest.as_str().split('#').next().unwrap_or_default().trim().to_string());
        out.push((c[1].to_string(), value));
        at = next;
    }
    out
}

/// `<NAME>.env` next to the config file, to be loaded before the config so `${VAR}` references resolve
/// (variables already set win: the caller merges). Returns its `(name, value)` pairs; every name is kept
/// out of the responder's environment. A missing file is an empty list.
pub fn load_env_file(file: &Path) -> Result<Vec<(String, String)>> {
    let env_file = file.parent().unwrap_or(Path::new("")).join(format!("{NAME}.env"));
    if !env_file.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(&env_file).map_err(|e| anyhow!("{}: {e}", env_file.display()))?;
    Ok(parse_env_text(&text))
}

/// JSON with `//` and `/* */` comments and trailing commas.
pub fn parse_jsonc(text: &str) -> Result<Value> {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                let mut j = i + 1;
                while j < bytes.len() && bytes[j] != b'"' {
                    j += if bytes[j] == b'\\' { 2 } else { 1 };
                }
                let end = (j + 1).min(bytes.len());
                out.push_str(&text[i..end]);
                i = end;
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i = text[i + 2..].find("*/").map_or(bytes.len(), |p| i + 2 + p + 2);
            }
            _ => {
                let ch = text[i..].chars().next().expect("inside the text");
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    // Like the original, the trailing-comma pass also looks inside strings.
    static TRAILING_COMMA: LazyLock<Regex> = LazyLock::new(|| Regex::new(r",(\s*[}\]])").expect("valid regex"));
    Ok(serde_json::from_str(&TRAILING_COMMA.replace_all(&out, "$1"))?)
}

pub fn load_config(explicit: Option<&str>, env: &Env) -> Result<Config> {
    let file = config_path(explicit, env);
    if !file.exists() {
        bail!("no config at {} (pass --config or set {ENV_PREFIX}_CONFIG; see examples/config.example.jsonc)", file.display());
    }
    // The env file next to the config: variables already set win; within the file the last line for a name wins
    // (appending a new value is how a key gets rotated).
    let mut from_file: IndexMap<String, String> = IndexMap::new();
    for (name, value) in load_env_file(&file)? {
        from_file.insert(name, value);
    }
    let mut env = env.clone();
    for (name, value) in &from_file {
        env.entry(name.clone()).or_insert_with(|| value.clone());
    }
    let text = fs::read_to_string(&file).map_err(|e| anyhow!("{}: {e}", file.display()))?;
    let raw = parse_jsonc(&text).map_err(|e| anyhow!("{}: {e}", file.display()))?;
    let mut config = build_config(&raw, &file, &env)?;
    for name in from_file.keys() {
        if !config.secret_env.contains(name) {
            config.secret_env.push(name.clone());
        }
        if let Some(value) = env.get(name).filter(|v| v.encode_utf16().count() >= 6)
            && !config.secrets.contains(value)
        {
            config.secrets.push(value.clone());
        }
    }
    sort_longest_first(&mut config.secrets);
    Ok(config)
}

fn sort_longest_first(secrets: &mut [String]) {
    secrets.sort_by_key(|s| std::cmp::Reverse(s.encode_utf16().count()));
}

// ---------- building the config from the parsed JSON ----------

type Obj = Map<String, Value>;

/// `o[key] ?? undefined`: missing and `null` are both absent.
fn present<'a>(o: &'a Obj, key: &str) -> Option<&'a Value> {
    o.get(key).filter(|v| !v.is_null())
}

fn obj<'a>(v: &'a Value, at: &str) -> Result<&'a Obj> {
    v.as_object().ok_or_else(|| anyhow!("{at}: expected an object"))
}

fn str_of(o: &Obj, key: &str, at: &str, fallback: Option<&str>) -> Result<String> {
    match present(o, key).map(|v| v.as_str()).unwrap_or(fallback) {
        Some(s) if !s.is_empty() => Ok(s.to_string()),
        _ => bail!("{at}.{key}: expected a non-empty string"),
    }
}

fn opt_str(o: &Obj, key: &str, at: &str) -> Result<Option<String>> {
    if o.contains_key(key) { str_of(o, key, at, None).map(Some) } else { Ok(None) }
}

/// A TCP port: a whole number 1-65535 (a cast would quietly connect somewhere else).
fn port_of(n: f64, at: &str) -> Result<u16> {
    if n.fract() != 0.0 || !(1.0..=65535.0).contains(&n) {
        bail!("{at}.port: expected a port number (1-65535)");
    }
    Ok(n as u16)
}

fn num_of(o: &Obj, key: &str, at: &str, fallback: f64) -> Result<f64> {
    let v = match present(o, key) {
        Some(v) => v.as_f64(),
        None => Some(fallback),
    };
    match v {
        Some(n) if n.is_finite() && n > 0.0 => Ok(n),
        _ => bail!("{at}.{key}: expected a positive number"),
    }
}

fn bool_of(o: &Obj, key: &str, at: &str, fallback: bool) -> Result<bool> {
    match present(o, key) {
        None => Ok(fallback),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => bail!("{at}.{key}: expected true or false"),
    }
}

fn strs_of(o: &Obj, key: &str, at: &str, fallback: &[&str]) -> Result<Vec<String>> {
    match present(o, key) {
        None => Ok(fallback.iter().map(|s| (*s).to_string()).collect()),
        Some(Value::Array(items)) => {
            items.iter().map(|x| x.as_str().map(str::to_string)).collect::<Option<Vec<_>>>().ok_or_else(|| anyhow!("{at}.{key}: expected a list of strings"))
        }
        Some(_) => bail!("{at}.{key}: expected a list of strings"),
    }
}

fn record_of(o: &Obj, key: &str, at: &str) -> Result<IndexMap<String, String>> {
    let empty = Value::Object(Map::new());
    let r = obj(present(o, key).unwrap_or(&empty), &format!("{at}.{key}"))?;
    let mut out = IndexMap::new();
    for (k, x) in r {
        match x.as_str() {
            Some(s) => out.insert(k.clone(), s.to_string()),
            None => bail!("{at}.{key}.{k}: expected a string"),
        };
    }
    Ok(out)
}

fn one_of<'a>(o: &Obj, key: &str, at: &str, values: &[&'a str], fallback: Option<&'a str>) -> Result<&'a str> {
    let v = present(o, key).map(|v| v.as_str()).unwrap_or(fallback);
    match v.and_then(|s| values.iter().find(|candidate| **candidate == s)) {
        Some(found) => Ok(found),
        None => bail!("{at}.{key}: expected one of {}", values.join(", ")),
    }
}

/// `responder.command`: one argv for every mode, or an object with one per mode (a missing mode takes `act`,
/// `update`, `propose`, whichever is set first); without it, the preset the optional `agent` names (returned too,
/// so the caller knows the argv is a preset's).
fn responder_command_of(r: &Obj, agent: Option<&str>) -> Result<(ResponderCommand, Option<Agent>)> {
    // propose, update, act
    let mut given: [Option<Vec<String>>; 3] = [None, None, None];
    match present(r, "command") {
        None => {}
        Some(Value::Array(_)) => {
            let argv = strs_of(r, "command", "responder", &[])?;
            if !argv.is_empty() {
                given = [Some(argv.clone()), Some(argv.clone()), Some(argv)];
            }
        }
        Some(Value::Object(modes)) => {
            if modes.is_empty() {
                bail!("responder.command: set at least one of propose, update, act");
            }
            for key in modes.keys() {
                let slot = match key.as_str() {
                    "propose" => 0,
                    "update" => 1,
                    "act" => 2,
                    other => bail!("responder.command: unknown mode '{other}' (propose, update, act)"),
                };
                let argv = strs_of(modes, key, "responder.command", &[])?;
                if argv.is_empty() {
                    bail!("responder.command.{key}: expected a non-empty list of strings");
                }
                given[slot] = Some(argv);
            }
        }
        Some(_) => bail!("responder.command: expected a list of strings, or an object with propose, update and/or act lists"),
    }
    if given.iter().any(Option::is_some) {
        let fallback = given[2].clone().or_else(|| given[1].clone()).or_else(|| given[0].clone()).unwrap_or_default();
        let [propose, update, act] = given;
        return Ok((
            ResponderCommand {
                propose: propose.unwrap_or_else(|| fallback.clone()),
                update: update.unwrap_or_else(|| fallback.clone()),
                act: act.unwrap_or(fallback),
            },
            None,
        ));
    }
    let Some(name) = agent else {
        bail!("responder: set \"command\" (your agent CLI's argv, see the README) or a preset \"agent\" ({})", Agent::NAMES);
    };
    let Some(preset) = Agent::parse(name) else {
        bail!("responder: no preset \"{name}\"; set \"command\" to your agent CLI's argv (presets: {})", Agent::NAMES);
    };
    let argv = |mode: Mode| crate::responder::PRESETS.get(&(preset, mode)).cloned().unwrap_or_default();
    Ok((ResponderCommand { propose: argv(Mode::Propose), update: argv(Mode::Update), act: argv(Mode::Act) }, Some(preset)))
}

/// JS truthiness of a parsed JSON value.
fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|n| n != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// JS `String(value)` for what a config may hold.
fn js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => match n.as_f64() {
            Some(f) if f.fract() == 0.0 && f.abs() < 1e21 => format!("{}", f as i128),
            _ => n.to_string(),
        },
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        Value::Array(items) => items.iter().map(js_string).collect::<Vec<_>>().join(","),
        Value::Object(_) => "[object Object]".to_string(),
    }
}

/// Resolves `${VAR}` references and collects what they resolved to.
struct Interpolator<'a> {
    env: &'a Env,
    secrets: Vec<String>,
    secret_env: Vec<String>,
}

impl Interpolator<'_> {
    fn add_secret(&mut self, value: &str) {
        if !self.secrets.iter().any(|s| s == value) {
            self.secrets.push(value.to_string());
        }
    }

    fn add_secret_env(&mut self, name: &str) {
        if !self.secret_env.iter().any(|s| s == name) {
            self.secret_env.push(name.to_string());
        }
    }

    /// `${VAR}` anywhere in a string value; a missing variable is an error, never an empty credential.
    fn run(&mut self, value: &Value, at: &str) -> Result<Value> {
        static REFERENCE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}").expect("valid regex"));
        match value {
            Value::String(s) => {
                let mut out = String::with_capacity(s.len());
                let mut last = 0;
                for c in REFERENCE.captures_iter(s) {
                    let whole = c.get(0).expect("whole match");
                    let name = &c[1];
                    out.push_str(&s[last..whole.start()]);
                    let resolved = self.env.get(name).filter(|v| !v.is_empty()).ok_or_else(|| anyhow!("{at}: environment variable {name} is not set"))?;
                    self.add_secret_env(name);
                    if resolved.encode_utf16().count() >= 6 {
                        self.add_secret(resolved);
                    }
                    out.push_str(resolved);
                    last = whole.end();
                }
                out.push_str(&s[last..]);
                Ok(Value::String(out))
            }
            Value::Array(items) => items.iter().enumerate().map(|(i, v)| self.run(v, &format!("{at}[{i}]"))).collect::<Result<Vec<_>>>().map(Value::Array),
            Value::Object(map) => {
                let mut out = Map::new();
                for (k, v) in map {
                    out.insert(k.clone(), self.run(v, &format!("{at}.{k}"))?);
                }
                Ok(Value::Object(out))
            }
            other => Ok(other.clone()),
        }
    }
}

pub fn build_config(raw: &Value, file: &Path, env: &Env) -> Result<Config> {
    let mut interpolator = Interpolator { env, secrets: Vec::new(), secret_env: Vec::new() };
    let root = interpolator.run(raw, "config")?;
    let Some(root) = root.as_object() else { bail!("{}: expected a JSON object", file.display()) };
    let base = file.parent().unwrap_or(Path::new("")).to_path_buf();
    let path = |p: &str| -> PathBuf {
        let expanded = expand_home(p);
        if Path::new(&expanded).is_absolute() { PathBuf::from(expanded) } else { resolve(&base.join(expanded)) }
    };

    let mut names: Vec<String> = Vec::new();
    let mut collectors = Vec::new();
    if let Some(Value::Array(list)) = root.get("collectors") {
        for (i, value) in list.iter().enumerate() {
            let at = format!("collectors[{i}]");
            let c = obj(value, &at)?;
            let kind = one_of(c, "type", &at, &["github", "host", "docker", "ssh"], None)?;
            let default_name = match (kind, c.get("host").and_then(Value::as_str)) {
                ("ssh", Some(host)) => host.rsplit_once('@').map_or(host, |(_, h)| h).to_string(),
                _ => kind.to_string(),
            };
            let name = str_of(c, "name", &at, Some(&default_name))?;
            if names.contains(&name) {
                bail!("{at}.name: '{name}' is used twice; give each collector its own name");
            }
            names.push(name.clone());
            collectors.push(match kind {
                "github" => CollectorConfig::Github(GithubCollector {
                    token: str_of(c, "token", &at, None)?,
                    api_url: str_of(c, "apiUrl", &at, Some("https://api.github.com"))?.trim_end_matches('/').to_string(),
                    repos: strs_of(c, "repos", &at, &[])?,
                    exclude: strs_of(c, "exclude", &at, &[])?,
                    include_forks: bool_of(c, "includeForks", &at, false)?,
                    include_archived: bool_of(c, "includeArchived", &at, false)?,
                    max_file_bytes: num_of(c, "maxFileBytes", &at, 8_000_000.0)? as u64,
                    name,
                }),
                "host" => {
                    CollectorConfig::Host(HostCollector { root: path(&str_of(c, "root", &at, Some("/"))?), binaries: strs_of(c, "binaries", &at, &[])?, name })
                }
                "docker" => {
                    let tls = if c.contains_key("tls") { Some(obj(&c["tls"], &format!("{at}.tls"))?) } else { None };
                    let tls_file = |key: &str| -> Result<Option<PathBuf>> {
                        match tls {
                            Some(t) if t.contains_key(key) => Ok(Some(path(&str_of(t, key, &format!("{at}.tls"), None)?))),
                            _ => Ok(None),
                        }
                    };
                    let endpoint = str_of(c, "endpoint", &at, Some("unix:///var/run/docker.sock"))?;
                    let exec = bool_of(c, "exec", &at, false)?;
                    let tls = match tls {
                        Some(_) => Some(DockerTls { ca: tls_file("ca")?, cert: tls_file("cert")?, key: tls_file("key")? }),
                        None => None,
                    };
                    CollectorConfig::Docker(DockerCollector { name, endpoint, tls, exec })
                }
                _ => CollectorConfig::Ssh(SshCollector {
                    host: str_of(c, "host", &at, None)?,
                    port: if c.contains_key("port") { Some(port_of(num_of(c, "port", &at, 22.0)?, &at)?) } else { None },
                    identity_file: if c.contains_key("identityFile") { Some(path(&str_of(c, "identityFile", &at, None)?)) } else { None },
                    ssh_options: strs_of(c, "sshOptions", &at, &[])?,
                    sudo: bool_of(c, "sudo", &at, true)?,
                    docker: bool_of(c, "docker", &at, true)?,
                    timeout_seconds: num_of(c, "timeoutSeconds", &at, 600.0)?,
                    name,
                }),
            });
        }
    }
    if collectors.is_empty() {
        bail!("collectors: add at least one, e.g. {{ \"type\": \"github\", \"token\": \"${{GITHUB_TOKEN}}\" }}");
    }

    // The classifier is on with a key, from the config or CLASSIFIER_API_KEY, or keyless with `"anonymous": true`
    // (classifier.dev's free tier, its limits apply); `"classifier": false` turns it off.
    let mut classifier = None;
    if root.get("classifier") != Some(&Value::Bool(false)) {
        let empty = Map::new();
        let c = if root.contains_key("classifier") { obj(&root["classifier"], "classifier")? } else { &empty };
        let own_key = c.get("apiKey").and_then(Value::as_str);
        let api_key = own_key.map(str::to_string).or_else(|| env.get("CLASSIFIER_API_KEY").cloned()).or_else(|| env.get("CLASSIFY_API_KEY").cloned());
        if let (false, Some(key)) = (c.contains_key("apiKey"), api_key.as_deref().filter(|k| !k.is_empty())) {
            interpolator.add_secret_env(if env.get("CLASSIFIER_API_KEY").is_some_and(|k| !k.is_empty()) { "CLASSIFIER_API_KEY" } else { "CLASSIFY_API_KEY" });
            interpolator.add_secret(key);
        }
        let has_key = api_key.as_deref().is_some_and(|k| !k.is_empty());
        if has_key || bool_of(c, "anonymous", "classifier", false)? {
            classifier = Some(ClassifierConfig {
                api_key: api_key.filter(|k| !k.is_empty()),
                url: str_of(c, "url", "classifier", Some("https://classifier.dev/v1/classify"))?,
                model: str_of(c, "model", "classifier", Some("jev"))?,
                tier: str_of(c, "tier", "classifier", Some("fast"))?,
                timeout_seconds: num_of(c, "timeoutSeconds", "classifier", 20.0)?,
            });
        }
    }

    let mut responder = None;
    if truthy(root.get("responder")) {
        let r = obj(&root["responder"], "responder")?;
        let agent = opt_str(r, "agent", "responder")?;
        let (command, preset) = responder_command_of(r, agent.as_deref())?;
        let shipped = shipped_brief();
        let brief = path(&str_of(r, "brief", "responder", Some(&shipped.to_string_lossy()))?);
        if brief != shipped {
            for file in ["common.md", "triage.md"] {
                if !brief.join(file).exists() {
                    bail!("responder.brief: {} has no {file} (it is a directory like the shipped agent/respond)", brief.display());
                }
            }
        }
        let reach = strs_of(r, "reach", "responder", &[])?;
        let command = match preset {
            // Propose runs without a shell; the reach-the-user commands are its one exception. Only the preset is touched: a user's own command is theirs.
            Some(Agent::Claude) => ResponderCommand { propose: crate::responder::allow_reach(&command.propose, &reach), ..command },
            _ => command,
        };
        responder = Some(ResponderConfig {
            agent,
            command,
            brief,
            notes: opt_str(r, "notes", "responder")?,
            act_on: strs_of(r, "actOn", "responder", &[])?,
            update_when_fixed: bool_of(r, "updateWhenFixed", "responder", DEFAULT_UPDATE_WHEN_FIXED)?,
            update_except: strs_of(r, "updateExcept", "responder", &[])?,
            max_per_cycle: num_of(r, "maxPerCycle", "responder", 2.0)?,
            timeout_minutes: num_of(r, "timeoutMinutes", "responder", 60.0)?,
            cwd: opt_str(r, "cwd", "responder")?.map(|cwd| path(&cwd)),
            env: record_of(r, "env", "responder")?,
            reach,
        });
    }

    let mut notify = Vec::new();
    if let Some(Value::Array(list)) = root.get("notify") {
        for (i, value) in list.iter().enumerate() {
            let at = format!("notify[{i}]");
            let n = obj(value, &at)?;
            // Notifiers interrupt the user: by default they get urgent one-liners only. Everything else lands in reports/ and the inbox for the agent in charge.
            let mut events = Vec::new();
            for e in strs_of(n, "events", &at, &["urgent"])? {
                match NOTIFY_EVENTS.iter().find(|event| event.as_str() == e) {
                    Some(event) => events.push(*event),
                    None => bail!("{at}.events: '{e}' is not {}", NOTIFY_EVENTS.map(NotifyEvent::as_str).join(", ")),
                }
            }
            let kind = match one_of(n, "type", &at, &["telegram", "slack", "webhook", "email", "command"], None)? {
                "telegram" => {
                    let bot_token = str_of(n, "botToken", &at, None)?;
                    let chat_id = match present(n, "chatId") {
                        Some(v) => js_string(v),
                        None => str_of(n, "chatId", &at, None)?,
                    };
                    let replies = bool_of(n, "replies", &at, false)?;
                    if replies {
                        if responder.is_none() {
                            bail!("{at}.replies: needs a responder (its command runs the agent in charge)");
                        }
                        if notify
                            .iter()
                            .any(|other: &NotifierConfig| matches!(&other.kind, NotifierKind::Telegram { bot_token: t, replies: true, .. } if *t == bot_token))
                        {
                            bail!("{at}.replies: another notifier already reads this bot");
                        }
                    }
                    NotifierKind::Telegram { bot_token, chat_id, replies }
                }
                "slack" => NotifierKind::Slack { webhook_url: str_of(n, "webhookUrl", &at, None)? },
                "webhook" => NotifierKind::Webhook { url: str_of(n, "url", &at, None)?, headers: record_of(n, "headers", &at)? },
                "email" => {
                    let port = port_of(num_of(n, "port", &at, 587.0)?, &at)?;
                    let to = match n.get("to") {
                        Some(Value::String(one)) => vec![one.clone()],
                        _ => strs_of(n, "to", &at, &[])?,
                    };
                    if to.is_empty() {
                        bail!("{at}.to: list at least one address");
                    }
                    let host = str_of(n, "host", &at, None)?;
                    let security = match one_of(n, "security", &at, &["tls", "starttls", "none"], Some(if port == 465 { "tls" } else { "starttls" }))? {
                        "tls" => EmailSecurity::Tls,
                        "starttls" => EmailSecurity::Starttls,
                        _ => EmailSecurity::None,
                    };
                    NotifierKind::Email {
                        host,
                        port,
                        security,
                        user: opt_str(n, "user", &at)?,
                        pass: opt_str(n, "pass", &at)?,
                        from: str_of(n, "from", &at, None)?,
                        to,
                    }
                }
                _ => {
                    let command = strs_of(n, "command", &at, &[])?;
                    if command.is_empty() {
                        bail!("{at}.command: expected argv");
                    }
                    NotifierKind::Command { command }
                }
            };
            notify.push(NotifierConfig { events, kind });
        }
    }

    let mut vendors = Vec::new();
    if let Some(Value::Array(list)) = root.get("vendors") {
        for (i, value) in list.iter().enumerate() {
            let at = format!("vendors[{i}]");
            if let Some(id) = value.as_str().filter(|s| !s.is_empty()) {
                vendors.push(VendorConfig { id: id.to_lowercase(), name: None, aliases: Vec::new(), feeds: Vec::new() });
                continue;
            }
            let v = obj(value, &at)?;
            let mut feeds = Vec::new();
            if let Some(Value::Array(list)) = v.get("feeds") {
                for (j, f) in list.iter().enumerate() {
                    let feed_at = format!("{at}.feeds[{j}]");
                    let feed = obj(f, &feed_at)?;
                    let url = str_of(feed, "url", &feed_at, None)?;
                    let kind = match one_of(feed, "kind", &feed_at, &["status", "security"], Some("status"))? {
                        "status" => VendorFeedKind::Status,
                        _ => VendorFeedKind::Security,
                    };
                    feeds.push(VendorFeed { url, kind });
                }
            }
            vendors.push(VendorConfig {
                id: str_of(v, "id", &at, None)?.to_lowercase(),
                name: opt_str(v, "name", &at)?,
                aliases: strs_of(v, "aliases", &at, &[])?.into_iter().map(|a| a.to_lowercase()).collect(),
                feeds,
            });
        }
    }

    let state_dir = {
        let from_env = env.get(&format!("{ENV_PREFIX}_STATE_DIR")).filter(|s| !s.is_empty());
        let from_config = root.get("stateDir").and_then(Value::as_str);
        match (from_env, from_config) {
            (Some(dir), _) => path(dir),
            (None, Some(dir)) => path(dir),
            (None, None) => path(&home_dir().join(".local").join("state").join(NAME).to_string_lossy()),
        }
    };
    let timezone_default = env
        .get("TZ")
        .filter(|tz| !tz.is_empty())
        .cloned()
        .or_else(|| jiff::tz::TimeZone::system().iana_name().map(str::to_string))
        .unwrap_or_else(|| "UTC".to_string());

    let poll_minutes = num_of(root, "pollMinutes", "config", 5.0)?;
    let inventory_hours = num_of(root, "inventoryHours", "config", 1.0)?;
    let timezone = str_of(root, "timezone", "config", Some(&timezone_default))?;
    let priority = strs_of(root, "priority", "config", &[])?;
    let disabled_sources = strs_of(root, "disabledSources", "config", &[])?;
    let news = bool_of(root, "news", "config", true)?;
    let ignore_vendors = strs_of(root, "ignoreVendors", "config", &[])?.into_iter().map(|v| v.to_lowercase()).collect();
    let rotation_map = opt_str(root, "rotationMap", "config")?.map(|p| path(&p));
    let runbooks = opt_str(root, "runbooks", "config")?.map(|p| path(&p));

    let mut secrets = interpolator.secrets;
    sort_longest_first(&mut secrets);
    Ok(Config {
        file: file.to_path_buf(),
        state_dir,
        poll_minutes,
        inventory_hours,
        timezone,
        priority,
        disabled_sources,
        news,
        collectors,
        vendors,
        ignore_vendors,
        rotation_map,
        runbooks,
        classifier,
        responder,
        notify,
        secrets,
        secret_env: interpolator.secret_env,
    })
}

/// Replaces every configured secret in text bound for logs, state or notifications.
pub fn redact(config: &Config, text: &str) -> String {
    let mut out = text.to_string();
    for secret in config.secrets.iter().filter(|s| !s.is_empty()) {
        out = out.replace(secret.as_str(), "[redacted]");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn env(pairs: &[(&str, &str)]) -> Env {
        pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect()
    }

    fn build(raw: Value, env: &Env) -> Result<Config> {
        build_config(&raw, Path::new("/x/config.json"), env)
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cvecondor-config-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("creates");
        dir
    }

    #[test]
    fn parse_jsonc_drops_comments_and_trailing_commas_but_keeps_strings() {
        let text = r#"{
  // a line comment
  "url": "https://example.com/a//b", /* a block
  comment */
  "list": [1, 2, 3,],
  "note": "has /* not a comment */ inside",
  "escaped": "quote \" // still a string",
}"#;
        let v = parse_jsonc(text).expect("parses");
        assert_eq!(v["url"], "https://example.com/a//b");
        assert_eq!(v["list"], json!([1, 2, 3]));
        assert_eq!(v["note"], "has /* not a comment */ inside");
        assert_eq!(v["escaped"], "quote \" // still a string");
        assert!(parse_jsonc("{ nope }").is_err());
        assert!(parse_jsonc("/* unterminated {").is_err());
    }

    #[test]
    fn a_secret_the_config_references_must_be_set() {
        let raw = json!({ "collectors": [{ "type": "github", "token": "${GITHUB_TOKEN}" }] });
        let err = build(raw.clone(), &env(&[])).expect_err("unset variable").to_string();
        assert_eq!(err, "config.collectors[0].token: environment variable GITHUB_TOKEN is not set");
        assert!(build(raw.clone(), &env(&[("GITHUB_TOKEN", "")])).is_err(), "an empty variable is not a credential");
        let config = build(raw, &env(&[("GITHUB_TOKEN", "github_pat_11ABCDEFG0123456789_secretvalue")])).expect("builds");
        let CollectorConfig::Github(github) = &config.collectors[0] else { panic!("a github collector") };
        assert_eq!(github.token, "github_pat_11ABCDEFG0123456789_secretvalue");
        assert_eq!(config.secret_env, ["GITHUB_TOKEN"]);
        assert_eq!(redact(&config, "token github_pat_11ABCDEFG0123456789_secretvalue was printed"), "token [redacted] was printed");
    }

    #[test]
    fn short_values_are_not_redacted_and_longer_secrets_go_first() {
        let config = build(
            json!({ "collectors": [{ "type": "github", "token": "${A}" }], "notify": [{ "type": "slack", "webhookUrl": "https://hooks.example.com/${B}/${C}" }] }),
            &env(&[("A", "abcdef"), ("B", "abcdef123456"), ("C", "xy")]),
        )
        .expect("builds");
        assert_eq!(config.secrets, ["abcdef123456", "abcdef"], "longest first, `xy` is too short to redact");
        assert_eq!(config.secret_env, ["A", "B", "C"], "every name is kept out of the responder");
        assert_eq!(redact(&config, "abcdef123456 abcdef xy"), "[redacted] [redacted] xy");
    }

    #[test]
    fn defaults_and_validation_messages() {
        let config = build(json!({ "collectors": [{ "type": "github", "token": "t" }, { "type": "ssh", "host": "root@web1.example.com" }, { "type": "host" }, { "type": "docker" }] }), &env(&[("TZ", "Europe/London")])).expect("builds");
        assert_eq!(config.collectors.iter().map(CollectorConfig::name).collect::<Vec<_>>(), ["github", "web1.example.com", "host", "docker"]);
        assert_eq!((config.poll_minutes, config.inventory_hours, config.news, config.timezone.as_str()), (5.0, 1.0, true, "Europe/London"));
        let CollectorConfig::Ssh(ssh) = &config.collectors[1] else { panic!("ssh") };
        assert_eq!((ssh.sudo, ssh.docker, ssh.timeout_seconds, ssh.port), (true, true, 600.0, None));
        let CollectorConfig::Docker(docker) = &config.collectors[3] else { panic!("docker") };
        assert_eq!(docker.endpoint, "unix:///var/run/docker.sock");
        assert!(config.classifier.is_none() && config.responder.is_none() && config.notify.is_empty());

        let msg = |raw: Value| build(raw, &env(&[])).expect_err("invalid").to_string();
        assert_eq!(msg(json!({})), "collectors: add at least one, e.g. { \"type\": \"github\", \"token\": \"${GITHUB_TOKEN}\" }");
        assert_eq!(msg(json!({ "collectors": [{ "type": "nope" }] })), "collectors[0].type: expected one of github, host, docker, ssh");
        assert_eq!(
            msg(json!({ "collectors": [{ "type": "host" }, { "type": "host" }] })),
            "collectors[1].name: 'host' is used twice; give each collector its own name"
        );
        assert_eq!(msg(json!({ "collectors": [{ "type": "github" }] })), "collectors[0].token: expected a non-empty string");
        assert_eq!(msg(json!({ "collectors": [{ "type": "host" }], "pollMinutes": 0 })), "config.pollMinutes: expected a positive number");
        assert_eq!(msg(json!({ "collectors": [{ "type": "host" }], "priority": "api" })), "config.priority: expected a list of strings");
        assert_eq!(
            msg(json!({ "collectors": [{ "type": "host" }], "responder": {} })),
            "responder: set \"command\" (your agent CLI's argv, see the README) or a preset \"agent\" (claude, codex, omp)"
        );
        assert_eq!(
            msg(json!({ "collectors": [{ "type": "host" }], "responder": { "agent": "gemini" } })),
            "responder: no preset \"gemini\"; set \"command\" to your agent CLI's argv (presets: claude, codex, omp)"
        );
        assert_eq!(
            msg(json!({ "collectors": [{ "type": "host" }], "notify": [{ "type": "email", "host": "h", "from": "f", "to": [] }] })),
            "notify[0].to: list at least one address"
        );
        assert_eq!(
            msg(json!({ "collectors": [{ "type": "host" }], "notify": [{ "type": "slack", "webhookUrl": "u", "events": ["case", "nope"] }] })),
            "notify[0].events: 'nope' is not urgent, case, report, secrets"
        );
        assert_eq!(msg(json!([1])), "/x/config.json: expected a JSON object");
    }

    #[test]
    fn paths_resolve_against_the_config_and_the_responder_defaults_hold() {
        let config = build(
            json!({ "stateDir": "state", "rotationMap": "maps/../rotation.json", "collectors": [{ "type": "host", "root": "/host/" }, { "type": "docker", "name": "d", "tls": { "ca": "certs/ca.pem" } }],
                     "responder": { "agent": "claude", "cwd": "work", "env": { "A": "b" } }, "vendors": ["Vercel", { "id": "Acme", "aliases": ["ACME Cloud"], "feeds": [{ "url": "https://status.example.com/rss" }] }],
                     "ignoreVendors": ["Foo"], "notify": [{ "type": "telegram", "botToken": "t", "chatId": -100123 }, { "type": "email", "host": "h", "port": 465, "from": "f", "to": "me@example.com" }] }),
            &env(&[]),
        )
        .expect("builds");
        assert_eq!(config.state_dir, Path::new("/x/state"));
        assert_eq!(config.rotation_map.as_deref(), Some(Path::new("/x/rotation.json")));
        let CollectorConfig::Host(host) = &config.collectors[0] else { panic!("host") };
        assert_eq!(host.root, Path::new("/host/"), "an absolute path is kept as written");
        let CollectorConfig::Docker(docker) = &config.collectors[1] else { panic!("docker") };
        assert_eq!(docker.tls.as_ref().and_then(|t| t.ca.as_deref()), Some(Path::new("/x/certs/ca.pem")));
        let r = config.responder.as_ref().expect("responder");
        assert_eq!((r.agent.as_deref(), r.update_when_fixed, r.max_per_cycle, r.timeout_minutes), (Some("claude"), true, 2.0, 60.0));
        assert_eq!(r.command.for_mode(Mode::Propose)[..3], ["claude", "-p", "--output-format"], "the preset fills every mode");
        assert_eq!(r.command.act, crate::responder::PRESETS[&(Agent::Claude, Mode::Act)]);
        assert_eq!(r.cwd.as_deref(), Some(Path::new("/x/work")));
        assert_eq!(r.brief, shipped_brief());
        assert_eq!(config.vendors[0], VendorConfig { id: "vercel".into(), name: None, aliases: vec![], feeds: vec![] });
        assert_eq!(config.vendors[1].aliases, ["acme cloud"]);
        assert_eq!(config.vendors[1].feeds[0].kind, VendorFeedKind::Status);
        assert_eq!(config.ignore_vendors, ["foo"]);
        let NotifierKind::Telegram { chat_id, .. } = &config.notify[0].kind else { panic!("telegram") };
        assert_eq!(chat_id, "-100123", "a numeric chat id is kept as text");
        assert_eq!(config.notify[0].events, [NotifyEvent::Urgent], "a notifier gets urgent one-liners unless it lists more");
        let listed = build(json!({ "collectors": [{ "type": "host" }], "notify": [{ "type": "slack", "webhookUrl": "u", "events": ["urgent", "case", "report", "secrets"] }] }), &env(&[])).expect("builds");
        assert_eq!(listed.notify[0].events, NOTIFY_EVENTS);
        let test = build(json!({ "collectors": [{ "type": "host" }], "notify": [{ "type": "slack", "webhookUrl": "u", "events": ["test"] }] }), &env(&[]));
        assert_eq!(test.expect_err("test is not accepted").to_string(), "notify[0].events: 'test' is not urgent, case, report, secrets");
        let NotifierKind::Email { security, to, port, .. } = &config.notify[1].kind else { panic!("email") };
        assert_eq!((*security, to.as_slice(), *port), (EmailSecurity::Tls, &["me@example.com".to_string()][..], 465));
    }

    #[test]
    fn the_responder_command_is_one_argv_or_one_per_mode_and_beats_the_preset() {
        let command = |responder: Value| {
            build(json!({ "collectors": [{ "type": "host" }], "responder": responder }), &env(&[])).map(|c| c.responder.expect("responder").command)
        };
        let argv = |parts: &[&str]| parts.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();

        let one =
            command(json!({ "command": ["my-agent", "--prompt", "@{prompt}"], "agent": "gemini" })).expect("builds: agent is only a label next to command");
        assert_eq!(
            (one.propose.clone(), one.update.clone(), one.act.clone()),
            (argv(&["my-agent", "--prompt", "@{prompt}"]), one.propose.clone(), one.propose.clone())
        );

        let only_propose = command(json!({ "command": { "propose": ["a"] } })).expect("builds");
        assert_eq!((only_propose.propose, only_propose.update, only_propose.act), (argv(&["a"]), argv(&["a"]), argv(&["a"])));
        let update_and_propose = command(json!({ "command": { "propose": ["p"], "update": ["u"] } })).expect("builds");
        assert_eq!(
            (update_and_propose.propose, update_and_propose.update, update_and_propose.act),
            (argv(&["p"]), argv(&["u"]), argv(&["u"])),
            "a missing mode takes act, update, propose"
        );
        let act_and_propose = command(json!({ "command": { "propose": ["p"], "act": ["x"] } })).expect("builds");
        assert_eq!((act_and_propose.propose, act_and_propose.update, act_and_propose.act), (argv(&["p"]), argv(&["x"]), argv(&["x"])));

        assert_eq!(command(json!({ "command": {} })).expect_err("empty").to_string(), "responder.command: set at least one of propose, update, act");
        assert_eq!(
            command(json!({ "command": { "ship": ["a"] } })).expect_err("unknown").to_string(),
            "responder.command: unknown mode 'ship' (propose, update, act)"
        );
        assert_eq!(
            command(json!({ "command": { "act": [] } })).expect_err("empty argv").to_string(),
            "responder.command.act: expected a non-empty list of strings"
        );
        assert_eq!(
            command(json!({ "command": [], "agent": "omp" })).expect("an empty list is no command").act,
            argv(&["omp", "-p", "--no-session", "@{prompt}"])
        );
    }

    #[test]
    fn the_classifier_follows_its_key_and_the_anonymous_switch() {
        let collectors = json!([{ "type": "host" }]);
        let off = build(json!({ "collectors": collectors }), &env(&[])).expect("builds");
        assert!(off.classifier.is_none());
        let keyed = build(json!({ "collectors": collectors }), &env(&[("CLASSIFY_API_KEY", "classify-key-123")])).expect("builds");
        assert_eq!(keyed.classifier.as_ref().and_then(|c| c.api_key.as_deref()), Some("classify-key-123"));
        assert_eq!((keyed.secret_env.as_slice(), keyed.secrets.as_slice()), (&["CLASSIFY_API_KEY".to_string()][..], &["classify-key-123".to_string()][..]));
        let anonymous = build(json!({ "collectors": collectors, "classifier": { "anonymous": true } }), &env(&[])).expect("builds");
        let c = anonymous.classifier.expect("anonymous tier");
        assert_eq!(
            (c.api_key, c.url.as_str(), c.model.as_str(), c.tier.as_str(), c.timeout_seconds),
            (None, "https://classifier.dev/v1/classify", "jev", "fast", 20.0)
        );
        let disabled = build(json!({ "collectors": collectors, "classifier": false }), &env(&[("CLASSIFIER_API_KEY", "some-key-1")])).expect("builds");
        assert!(disabled.classifier.is_none());
    }

    #[test]
    fn the_env_file_next_to_the_config_is_loaded_and_kept_secret() {
        let dir = scratch("envfile");
        fs::write(
            dir.join("config.json"),
            r#"{ "stateDir": "state", "collectors": [{ "type": "github", "token": "${FILE_TOKEN}" }], "notify": [{ "type": "slack", "webhookUrl": "${SET_ALREADY}" }] }"#,
        )
        .expect("writes");
        fs::write(
            dir.join("cvecondor.env"),
            "# comment\nFILE_TOKEN=ghp_from_the_file # trailing\nexport OTHER_SECRET=\"line one\\nline two\"\nSET_ALREADY=from-the-file\nQUOTED='multi\nline'\nNO_VALUE=\n",
        )
        .expect("writes");
        let pairs = load_env_file(&dir.join("config.json")).expect("reads");
        assert_eq!(pairs[0], ("FILE_TOKEN".to_string(), "ghp_from_the_file".to_string()));
        assert_eq!(pairs[1], ("OTHER_SECRET".to_string(), "line one\nline two".to_string()));
        assert_eq!(pairs[3], ("QUOTED".to_string(), "multi\nline".to_string()));
        assert_eq!(pairs[4], ("NO_VALUE".to_string(), String::new()));

        let config =
            load_config(Some(dir.join("config.json").to_str().expect("utf-8")), &env(&[("SET_ALREADY", "https://hooks.example.com/real")])).expect("loads");
        let CollectorConfig::Github(github) = &config.collectors[0] else { panic!("github") };
        assert_eq!(github.token, "ghp_from_the_file");
        assert_eq!(config.state_dir, dir.join("state"));
        assert!(config.secret_env.iter().any(|n| n == "OTHER_SECRET"), "every name in the env file is kept out of the responder");
        assert!(config.secrets.contains(&"line one\nline two".to_string()));
        assert_eq!(config.secrets[0], "https://hooks.example.com/real", "longest first");
        let NotifierKind::Slack { webhook_url } = &config.notify[0].kind else { panic!("slack") };
        assert_eq!(webhook_url, "https://hooks.example.com/real", "variables already set win over the file");

        let missing = load_config(Some(dir.join("nope.json").to_str().expect("utf-8")), &env(&[])).expect_err("no config").to_string();
        assert!(missing.starts_with(&format!("no config at {}/nope.json (pass --config or set CVECONDOR_CONFIG;", dir.display())), "{missing}");
        fs::remove_dir_all(&dir).expect("cleans");
    }

    #[test]
    fn config_path_prefers_the_flag_then_the_environment() {
        assert_eq!(config_path(Some("/a/b.json"), &env(&[("CVECONDOR_CONFIG", "/c/d.json")])), Path::new("/a/b.json"));
        assert_eq!(config_path(None, &env(&[("CVECONDOR_CONFIG", "/c/../c/d.json")])), Path::new("/c/d.json"));
        assert!(
            config_path(None, &env(&[])).ends_with(".config/cvecondor/config.json") || config_path(None, &env(&[])).ends_with(".config/cvecondor/config.jsonc")
        );
    }

    #[test]
    fn the_shipped_brief_is_found_and_embedded() {
        assert!(shipped_brief().join("triage.md").exists());
        for (file, text) in SHIPPED_BRIEF_FILES {
            assert_eq!(read_brief(&shipped_brief(), file).expect("reads"), *text);
        }
        assert!(read_brief(Path::new("/nonexistent"), "common.md").is_err());
    }
}
