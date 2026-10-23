// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! What a repo says it runs, from its files alone: lockfiles → OSV package
//! coordinates, Dockerfile and compose images → images, runtimes and base OSes,
//! version files → runtimes, deploy configs → platforms. Regex/JSON only: no
//! package manager or build tool runs, so a hostile repo can't execute anything.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use indexmap::IndexMap;
use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::util::{is_js_space, js_regex, js_trim};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockedPackage {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RepoFindingKind {
    Package,
    Runtime,
    Image,
    Os,
    Platform,
}

impl RepoFindingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Package => "package",
            Self::Runtime => "runtime",
            Self::Image => "image",
            Self::Os => "os",
            Self::Platform => "platform",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoFinding {
    pub kind: RepoFindingKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<String>,
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<bool>,
}

pub const LOCKFILES: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "bun.lock",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements.txt",
    "uv.lock",
    "poetry.lock",
    "Cargo.lock",
    "composer.lock",
    "go.sum",
    "go.mod",
    "Gemfile.lock",
];

const NPM_LOCKS: [&str; 6] = ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"];

/// A lazily compiled regex literal, one static per call site.
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

// JS `.` stops at a line terminator (`\n`, `\r`, U+2028, U+2029); the regex crate's only at `\n`. The TS patterns that use `.*` are
// written with `[^\n\r\u{2028}\u{2029}]*` so CRLF text behaves as it did under Node. `\d` and `\w` are spelled out as ASCII classes
// for the same reason (JS's are ASCII, the regex crate's are Unicode).

/// JS `text.split(/\r?\n/)`: only a `\r` right before a `\n` is dropped.
fn split_lines(text: &str) -> Vec<&str> {
    let mut lines: Vec<&str> = text.split('\n').collect();
    let last = lines.len() - 1;
    for line in &mut lines[..last] {
        *line = line.strip_suffix('\r').unwrap_or(line);
    }
    lines
}

fn plain_version(version: &str) -> bool {
    re!(r"^[0-9]+(\.[0-9]+)*([-.+~][0-9A-Za-z.+~-]*)?$").is_match(version)
}

fn base_of(path: &str) -> &str {
    &path[path.rfind('/').map_or(0, |i| i + 1)..]
}

fn dir_of(path: &str) -> &str {
    &path[..path.rfind('/').unwrap_or(0)]
}

fn is_lockfile(base: &str) -> bool {
    LOCKFILES.contains(&base) || (base.starts_with("requirements") && base.ends_with(".txt"))
}

fn finding(kind: RepoFindingKind, name: &str, version: &str) -> RepoFinding {
    RepoFinding { kind, ecosystem: None, name: name.to_string(), version: version.to_string(), dev: None }
}

/// The packages of a `[[package]]` TOML lockfile (uv, poetry, Cargo).
fn toml_packages(text: &str, ecosystem: &str) -> Vec<LockedPackage> {
    let mut out = Vec::new();
    for block in re!(r"(?m)^\[\[package\]\]\s*$").split(text).skip(1) {
        let name = re!(r#"(?m)^name\s*=\s*"([^"]+)""#).captures(block).map(|m| m[1].to_string());
        let version = re!(r#"(?m)^version\s*=\s*"([^"]+)""#).captures(block).map(|m| m[1].to_string());
        // Poetry 1 marks `category = "dev"`; Poetry 2 lists `groups`, dev-only when "main" is absent.
        let groups = re!(r"(?m)^groups\s*=\s*\[([^\]]*)\]").captures(block).map(|m| m[1].to_string());
        let dev = re!(r#"(?m)^category\s*=\s*"dev""#).is_match(block) || groups.is_some_and(|g| !g.contains("\"main\""));
        if let (Some(name), Some(version)) = (name, version) {
            out.push(LockedPackage { ecosystem: ecosystem.to_string(), name, version, dev: dev.then_some(true) });
        }
    }
    out
}

/// The dependencies of a composer lockfile section.
#[derive(Deserialize)]
struct ComposerPackage {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
}

#[derive(Deserialize)]
struct ComposerLock {
    #[serde(default)]
    packages: Option<Vec<ComposerPackage>>,
    #[serde(default, rename = "packages-dev")]
    packages_dev: Option<Vec<ComposerPackage>>,
}

fn add(out: &mut Vec<LockedPackage>, ecosystem: &str, name: Option<&str>, version: Option<&str>, dev: bool) {
    if let (Some(name), Some(version)) = (name, version)
        && !name.is_empty()
        && plain_version(version)
    {
        out.push(LockedPackage { ecosystem: ecosystem.to_string(), name: name.to_string(), version: version.to_string(), dev: dev.then_some(true) });
    }
}

/// JS truthiness of a JSON value (`entry.dev`, `entry.link`).
fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// The v1 lockfile's nested `dependencies` (objects of objects). An entry of another type is skipped, not fatal.
fn add_npm_tree(out: &mut Vec<LockedPackage>, deps: Option<&Value>) {
    for (name, entry) in deps.and_then(Value::as_object).into_iter().flatten() {
        let Some(entry) = entry.as_object() else { continue };
        add(out, "npm", Some(name), entry.get("version").and_then(Value::as_str), truthy(entry.get("dev")));
        add_npm_tree(out, entry.get("dependencies"));
    }
}

/// Reads one lockfile into `out`. An error leaves what was read so far, as the TS `try` did.
fn read_lockfile(base: &str, text: &str, out: &mut Vec<LockedPackage>) -> anyhow::Result<()> {
    if base == "package-lock.json" || base == "npm-shrinkwrap.json" {
        // Read dynamically: in v2/v3 `dependencies` and friends are maps of range strings, and a field of the wrong
        // type must cost one entry, not the file.
        let lock: Value = serde_json::from_str(text)?;
        let packages = lock.get("packages");
        if truthy(packages) {
            for (path, entry) in packages.and_then(Value::as_object).into_iter().flatten() {
                let Some(entry) = entry.as_object() else { continue };
                if let Some(at) = path.rfind("node_modules/")
                    && !truthy(entry.get("link"))
                {
                    let name = entry.get("name").and_then(Value::as_str).unwrap_or(&path[at + "node_modules/".len()..]);
                    let dev = truthy(entry.get("dev")) || truthy(entry.get("devOptional"));
                    add(out, "npm", Some(name), entry.get("version").and_then(Value::as_str), dev);
                }
            }
        } else {
            add_npm_tree(out, lock.get("dependencies"));
        }
    } else if base == "bun.lock" {
        // JSONC with trailing commas.
        let lock: Value = serde_json::from_str(&re!(r",(\s*[}\]])").replace_all(text, "$1"))?;
        for entry in lock.get("packages").and_then(Value::as_object).into_iter().flat_map(|packages| packages.values()) {
            let spec = entry.as_array().and_then(|a| a.first()).and_then(Value::as_str).unwrap_or("");
            if let Some(at) = spec.rfind('@')
                && at > 0
            {
                add(out, "npm", Some(&spec[..at]), Some(&spec[at + 1..]), false);
            }
        }
    } else if base == "pnpm-lock.yaml" {
        for m in re!(r#"(?m)^ {2}['"]?/?((?:@[^/@\s'"]+/)?[^/@\s'"(]+)[@/]([0-9][^:(\s'"]*)"#).captures_iter(text) {
            add(out, "npm", Some(&m[1]), Some(&m[2]), false);
        }
    } else if base == "yarn.lock" {
        // JS splits on /\n(?=\S)/: a newline followed by a non-space character starts a block.
        let mut blocks = Vec::new();
        let mut start = 0;
        for (i, c) in text.char_indices() {
            if c == '\n' && text[i + 1..].chars().next().is_some_and(|next| !is_js_space(next)) {
                blocks.push(&text[start..i]);
                start = i + 1;
            }
        }
        blocks.push(&text[start..]);
        for block in blocks {
            let header = jsre!(r#"^"?((?:@[^@/\s"]+/)?[^@\s",]+)@"#).captures(block).map(|m| m.get(1).map_or("", |g| g.as_str()));
            let version = jsre!(r#"(?m)^\s+version:?\s+"?([^"\s]+)"?"#).captures(block).map(|m| m.get(1).map_or("", |g| g.as_str()));
            add(out, "npm", header, version, false);
        }
    } else if base.starts_with("requirements") && base.ends_with(".txt") {
        let dev = re!(r"^requirements[-_.](?:dev|test|tests|lint|docs)(?-u:\b)").is_match(base);
        for m in jsre!(r"(?m)^\s*([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)").captures_iter(text) {
            add(out, "PyPI", Some(&m[1]), Some(&m[2]), dev);
        }
    } else if base == "uv.lock" || base == "poetry.lock" {
        out.extend(toml_packages(text, "PyPI"));
    } else if base == "Cargo.lock" {
        out.extend(toml_packages(text, "crates.io"));
    } else if base == "composer.lock" {
        let lock: ComposerLock = serde_json::from_str(text)?;
        for (list, dev) in [(&lock.packages, false), (&lock.packages_dev, true)] {
            for p in list.iter().flatten() {
                // The TS reads `p.version.replace(...)`, which throws on a missing version and drops the rest.
                let Some(version) = &p.version else { return Ok(()) };
                add(out, "Packagist", p.name.as_deref(), Some(version.strip_prefix('v').unwrap_or(version)), dev);
            }
        }
    } else if base == "go.sum" {
        for m in jsre!(r"(?m)^(\S+) v(\S+?)(?:/go\.mod)? h1:").captures_iter(text) {
            add(out, "Go", Some(&m[1]), Some(&m[2]), false);
        }
    } else if base == "go.mod" {
        let mut block = false;
        for raw in text.split('\n') {
            let stripped = re!(r"//[^\n\r\u{2028}\u{2029}]*$").replace(raw, "");
            let line = js_trim(&stripped);
            if block && line == ")" {
                block = false;
            } else if re!(r"^require\s*\($").is_match(line) {
                block = true;
            } else {
                let pattern = if block { re!(r"^(\S+)\s+v(\S+)$") } else { re!(r"^require\s+(\S+)\s+v(\S+)$") };
                if let Some(m) = pattern.captures(line) {
                    add(out, "Go", Some(&m[1]), Some(&m[2]), false);
                }
            }
        }
    } else if base == "Gemfile.lock" {
        // Only `GEM` sections come from rubygems.org; 4-space entries are the resolved gems,
        // 6-space ones their constraints. A `-x86_64-linux` suffix is the platform build.
        let mut section = "";
        for line in split_lines(text) {
            if line.chars().next().is_some_and(|c| !is_js_space(c)) {
                section = js_trim(line);
            }
            if section == "GEM"
                && let Some(m) = re!(r"^ {4}([^\s(]+) \(([^)\s]+)\)$").captures(line)
            {
                add(out, "RubyGems", Some(&m[1]), Some(&re!(r"-[A-Za-z][^\n\r\u{2028}\u{2029}]*$").replace(&m[2], "")), false);
            }
        }
    }
    Ok(())
}

/// The packages a lockfile pins, as OSV coordinates. An unreadable lockfile gives what was read before the error (usually nothing).
pub fn parse_lockfile(file: &str, text: &str) -> Vec<LockedPackage> {
    let mut out = Vec::new();
    // An unreadable lockfile contributes nothing; the next refresh retries.
    let _ = read_lockfile(base_of(file), text, &mut out);
    let mut seen: IndexMap<String, LockedPackage> = IndexMap::new();
    for p in out {
        let key = format!("{}\0{}\0{}", p.ecosystem, p.name, p.version);
        match seen.get_mut(&key) {
            None => {
                seen.insert(key, p);
            }
            Some(before) => {
                if before.dev == Some(true) && p.dev != Some(true) {
                    before.dev = None;
                }
            }
        }
    }
    seen.into_values().collect()
}

// Runtimes a lockfile pins beside its packages.
fn lock_runtimes(base: &str, text: &str) -> Vec<RepoFinding> {
    if base == "go.mod" {
        let version = re!(r"(?m)^toolchain\s+go([0-9]+(?:\.[0-9]+)*)")
            .captures(text)
            .or_else(|| re!(r"(?m)^go\s+([0-9]+(?:\.[0-9]+)*)\s*$").captures(text))
            .map(|m| m[1].to_string());
        return version.map(|v| finding(RepoFindingKind::Runtime, "go", &v)).into_iter().collect();
    }
    if base == "Gemfile.lock" {
        let version = re!(r"(?m)^RUBY VERSION\s*\n\s+ruby ([0-9]+(?:\.[0-9]+)*)").captures(text).map(|m| m[1].to_string());
        return version.map(|v| finding(RepoFindingKind::Runtime, "ruby", &v)).into_iter().collect();
    }
    Vec::new()
}

// `${NAME}`, `$NAME`, `${NAME:-default}`, `${NAME:+alt}`. None when a variable has no value: the image is then unknowable.
fn substitute(text: &str, vars: &HashMap<String, String>) -> Option<String> {
    let mut missing = false;
    let out = re!(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-+])([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)").replace_all(text, |m: &Captures| {
        let name = m.get(1).or_else(|| m.get(4)).map_or("", |g| g.as_str());
        let value = vars.get(name);
        let op = m.get(2).map(|g| g.as_str());
        let word = m.get(3).map_or("", |g| g.as_str());
        let unset = value.is_none() || (op.is_some_and(|o| o.starts_with(':')) && value.is_some_and(String::is_empty));
        if op.is_some_and(|o| o.ends_with('-')) {
            return if unset { word.to_string() } else { value.cloned().unwrap_or_default() };
        }
        if op.is_some_and(|o| o.ends_with('+')) {
            return if unset { String::new() } else { word.to_string() };
        }
        if value.is_none() {
            missing = true;
        }
        value.cloned().unwrap_or_default()
    });
    if missing { None } else { Some(out.into_owned()) }
}

fn dockerfile_images(text: &str) -> Vec<String> {
    let mut args: HashMap<String, String> = HashMap::new();
    let mut stages: HashSet<String> = HashSet::new();
    let mut images = Vec::new();
    let mut staged = false;
    let joined = re!(r"\\[ \t]*\r?\n").replace_all(text, " ");
    for raw in split_lines(&joined) {
        let line = js_trim(raw);
        // Only ARGs before the first FROM are in scope for FROM lines.
        if !staged && let Some(arg) = re!(r"(?i)^ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(\S*))?").captures(line) {
            if let Some(value) = arg.get(2) {
                // JS `/^(['"])(.*)\1$/`: a value wrapped in one matching pair of quotes.
                let value = value.as_str();
                let unquoted = match value.chars().next() {
                    Some(q @ ('\'' | '"')) if value.len() >= 2 && value.ends_with(q) => &value[1..value.len() - 1],
                    _ => value,
                };
                args.insert(arg[1].to_string(), unquoted.to_string());
            }
            continue;
        }
        let Some(from) = re!(r"(?i)^FROM\s+([^\n\r\u{2028}\u{2029}]+)$").captures(line) else { continue };
        staged = true;
        let words: Vec<&str> = from[1].split_whitespace().filter(|word| !word.starts_with("--")).collect();
        let image = substitute(words.first().copied().unwrap_or(""), &args);
        if let Some(image) = image
            && !image.is_empty()
            && !stages.contains(&image.to_lowercase())
        {
            images.push(image);
        }
        if words.get(1).is_some_and(|w| w.eq_ignore_ascii_case("as"))
            && let Some(stage) = words.get(2)
        {
            stages.insert(stage.to_lowercase());
        }
    }
    images
}

fn compose_images(text: &str) -> Vec<String> {
    let mut images = Vec::new();
    // JS `(['"]?)([^'"\s#]+)\1`: an optional quote that must close after the name. Backreferences don't exist here: check the closer.
    for m in jsre!(r#"(?m)^\s*image:\s*(['"]?)([^'"\s#]+)"#).captures_iter(text) {
        let quote = &m[1];
        let name = m.get(2).expect("group 2 always participates");
        if !quote.is_empty() && !text[name.end()..].starts_with(quote) {
            continue;
        }
        if let Some(image) = substitute(name.as_str(), &HashMap::new())
            && !image.is_empty()
        {
            images.push(image);
        }
    }
    images
}

fn runtime_image(repository: &str) -> Option<&'static str> {
    Some(match repository {
        "node" => "node",
        "php" => "php",
        "python" => "python",
        "ruby" => "ruby",
        "golang" => "go",
        "oven/bun" => "bun",
        "denoland/deno" => "deno",
        "openjdk" | "eclipse-temurin" => "java",
        _ => return None,
    })
}

fn debian_release(word: &str) -> Option<&'static str> {
    Some(match word {
        "buster" => "10",
        "bullseye" => "11",
        "bookworm" => "12",
        "trixie" => "13",
        "forky" => "14",
        _ => return None,
    })
}

fn ubuntu_release(word: &str) -> Option<&'static str> {
    Some(match word {
        "bionic" => "18.04",
        "focal" => "20.04",
        "jammy" => "22.04",
        "noble" => "24.04",
        "oracular" => "24.10",
        "plucky" => "25.04",
        "questing" => "25.10",
        _ => return None,
    })
}

fn distro(name: &str, tag: &str) -> RepoFinding {
    let word = tag.split(['-', '_']).next().unwrap_or("");
    let os = |name: &str, version: &str, ecosystem: Option<String>| RepoFinding {
        kind: RepoFindingKind::Os,
        ecosystem,
        name: name.to_string(),
        version: version.to_string(),
        dev: None,
    };
    if name == "debian" {
        let major = re!(r"^([0-9]+)(?:\.[0-9]+)*$").captures(word).map(|m| m[1].to_string()).or_else(|| debian_release(word).map(str::to_string));
        return match major {
            Some(major) => os("Debian", &major, Some(format!("Debian:{major}"))),
            None => os("Debian", tag, None),
        };
    }
    if name == "ubuntu" {
        let version = if re!(r"^[0-9]+\.[0-9]+$").is_match(word) { Some(word) } else { ubuntu_release(word) };
        return match version {
            Some(version) => {
                let lts = if re!(r"^[0-9]*[02468]\.04$").is_match(version) { ":LTS" } else { "" };
                os("Ubuntu", version, Some(format!("Ubuntu:{version}{lts}")))
            }
            None => os("Ubuntu", tag, None),
        };
    }
    match re!(r"^([0-9]+\.[0-9]+)(?:\.[0-9]+)?$").captures(word) {
        Some(m) => os("Alpine", word, Some(format!("Alpine:v{}", &m[1]))),
        None => os("Alpine", tag, None),
    }
}

/// An image reference → the image itself, plus the runtime or base OS an official image's tag names.
fn image_findings(reference: &str) -> Vec<RepoFinding> {
    let bare = js_trim(reference.split('@').next().unwrap_or(""));
    if bare.is_empty() || bare == "scratch" {
        return Vec::new();
    }
    // `colon > slash` with -1 for "not found".
    let tagged = match (bare.rfind(':'), bare.rfind('/')) {
        (Some(colon), Some(slash)) => (colon > slash).then_some(colon),
        (Some(colon), None) => Some(colon),
        (None, _) => None,
    };
    let tag = tagged.map_or("", |colon| &bare[colon + 1..]);
    let mut parts: Vec<String> = tagged.map_or(bare, |colon| &bare[..colon]).to_lowercase().split('/').map(str::to_string).collect();
    let registry = if parts.len() > 1 && (parts[0].contains(['.', ':']) || parts[0] == "localhost") { Some(parts.remove(0)) } else { None };
    let hub = registry.as_deref().is_none_or(|r| r == "docker.io" || r == "index.docker.io");
    if hub && parts[0] == "library" && parts.len() > 1 {
        parts.remove(0);
    }
    let repository = parts.join("/");
    let version = if tag.is_empty() { "latest" } else { tag };
    let mut out = vec![finding(RepoFindingKind::Image, parts.last().map_or("", String::as_str), version)];
    let runtime = if hub { runtime_image(&repository) } else { None };
    // JS lookaheads `(?=$|[-_])` become a consumed `(?:[-_]|$)`: a digit run can only end at one of them, so the match is the same.
    let numeric = re!(r"^v?([0-9]+(?:\.[0-9]+)*)(?:[-_]|$)").captures(tag).map(|m| m[1].to_string());
    if let (Some(runtime), Some(numeric)) = (runtime, &numeric) {
        out.push(finding(RepoFindingKind::Runtime, runtime, numeric));
    }
    let php = re!(r"(?:^|[-_.])php-?([0-9]+(?:\.[0-9]+)*)(?:[-_]|$)").captures(tag).map(|m| m[1].to_string());
    if let Some(php) = php
        && runtime != Some("php")
    {
        out.push(finding(RepoFindingKind::Runtime, "php", &php));
    }
    if hub && ["debian", "ubuntu", "alpine"].contains(&repository.as_str()) {
        out.push(distro(&repository, version));
    }
    out
}

fn first_line(text: &str) -> String {
    split_lines(text)
        .into_iter()
        .map(|line| js_trim(&re!(r"#[^\n\r\u{2028}\u{2029}]*").replace(line, "")).to_string())
        .find(|line| !line.is_empty())
        .unwrap_or_default()
}

fn numeric_version(text: &str) -> Option<String> {
    re!(r"^v?([0-9]+(?:\.[0-9]+)*)$").captures(text).map(|m| m[1].to_string())
}

fn tool_version_name(tool: &str) -> Option<&'static str> {
    Some(match tool {
        "nodejs" | "node" => "node",
        "python" => "python",
        "ruby" => "ruby",
        "golang" | "go" => "go",
        "bun" => "bun",
        "deno" => "deno",
        "php" => "php",
        _ => return None,
    })
}

fn version_file_name(base: &str) -> Option<&'static str> {
    Some(match base {
        ".nvmrc" | ".node-version" => "node",
        ".python-version" => "python",
        ".ruby-version" => "ruby",
        _ => return None,
    })
}

fn runtime_file(base: &str, text: &str) -> Vec<RepoFinding> {
    let runtime = |name: &str, version: Option<String>| version.map(|v| finding(RepoFindingKind::Runtime, name, &v)).into_iter().collect::<Vec<_>>();
    if let Some(name) = version_file_name(base) {
        let line = first_line(text);
        return runtime(name, numeric_version(line.strip_prefix("ruby-").unwrap_or(&line)));
    }
    if base == "runtime.txt" {
        return runtime("python", re!(r"^python-([0-9]+(?:\.[0-9]+)*)$").captures(&first_line(text)).map(|m| m[1].to_string()));
    }
    split_lines(text)
        .into_iter()
        .flat_map(|line| {
            let line = re!(r"#[^\n\r\u{2028}\u{2029}]*").replace(line, "");
            let mut words = js_trim(&line).split_whitespace().map(str::to_string).collect::<Vec<_>>().into_iter();
            let name = words.next().and_then(|tool| tool_version_name(&tool));
            match name {
                Some(name) => runtime(name, words.find_map(|v| numeric_version(&v))),
                None => Vec::new(),
            }
        })
        .collect()
}

static PLATFORMS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    [
        (r"^railway\.(json|toml)$", "railway"),
        (r"^vercel\.json$", "vercel"),
        (r"^netlify\.toml$", "netlify"),
        (r"^fly\.toml$", "fly"),
        (r"^render\.yaml$", "render"),
        (r"^heroku\.yml$", "heroku"),
        (r"^wrangler\.(toml|jsonc?)$", "cloudflare"),
        (r"^firebase\.json$", "firebase"),
        (r"^amplify\.yml$", "aws"),
    ]
    .into_iter()
    .map(|(pattern, name)| (Regex::new(pattern).expect("valid regex"), name))
    .collect()
});

fn platform_of(path: &str, siblings: &[String]) -> Option<&'static str> {
    let base = base_of(path);
    if re!(r"(^|/)supabase/config\.toml$").is_match(path) {
        return Some("supabase");
    }
    if base == "app.json" {
        return siblings.iter().any(|s| base_of(s) == "Procfile" && dir_of(s) == dir_of(path)).then_some("heroku");
    }
    PLATFORMS.iter().find(|(pattern, _)| pattern.is_match(base)).map(|(_, name)| *name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileType {
    Lock,
    PackageJson,
    Pyproject,
    Dockerfile,
    Compose,
    Version,
    Platform,
}

fn file_type(path: &str) -> Option<FileType> {
    let base = base_of(path);
    if is_lockfile(base) {
        return Some(FileType::Lock);
    }
    if base == "package.json" {
        return Some(FileType::PackageJson);
    }
    if base == "pyproject.toml" {
        return Some(FileType::Pyproject);
    }
    // ASCII-only, so Unicode case folding (the Kelvin sign for `k`) stays off, as in JS.
    if re!(r"(?i-u)^(dockerfile|containerfile)(\.[A-Za-z0-9_.-]+)?$|\.dockerfile$").is_match(base) && !base.ends_with(".dockerignore") {
        return Some(FileType::Dockerfile);
    }
    if re!(r"^(docker-)?compose[A-Za-z0-9_.-]*\.ya?ml$").is_match(base) {
        return Some(FileType::Compose);
    }
    if version_file_name(base).is_some() || base == "runtime.txt" || base == ".tool-versions" {
        return Some(FileType::Version);
    }
    if base == "app.json" || platform_of(path, &[]).is_some() {
        return Some(FileType::Platform);
    }
    None
}

/// Under a vendored or generated directory: someone else's files, not what the repo runs.
pub fn is_vendored(path: &str) -> bool {
    re!(r"(^|/)(node_modules|vendor|\.git|dist|build|third_party|\.venv)/").is_match(path)
}

/// A file `parse_repo_file` reads something from.
pub fn is_repo_file(path: &str) -> bool {
    !is_vendored(path) && file_type(path).is_some()
}

/// A Dockerfile or compose file, which names the images the repo runs.
pub fn names_images(path: &str) -> bool {
    !is_vendored(path) && matches!(file_type(path), Some(FileType::Dockerfile | FileType::Compose))
}

/// The image references a Dockerfile or compose file names, as written (`scratch` included), without build stages
/// and without references whose variables have no value. `None` for any other file.
pub fn image_references(path: &str, text: &str) -> Option<Vec<String>> {
    if is_vendored(path) {
        return None;
    }
    match file_type(path) {
        Some(FileType::Dockerfile) => Some(dockerfile_images(text)),
        Some(FileType::Compose) => Some(compose_images(text)),
        _ => None,
    }
}

fn exact_pins(text: &str) -> anyhow::Result<Vec<LockedPackage>> {
    let pkg: Value = serde_json::from_str(text)?;
    let mut out = Vec::new();
    for (field, dev) in [("dependencies", false), ("optionalDependencies", false), ("devDependencies", true)] {
        for (name, spec) in pkg.get(field).and_then(Value::as_object).into_iter().flatten() {
            let version = spec.as_str().and_then(|spec| {
                re!(r"^=?v?([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$").captures(js_trim(spec)).map(|m| m[1].to_string())
            });
            if let Some(version) = version {
                out.push(LockedPackage { ecosystem: "npm".to_string(), name: name.clone(), version, dev: dev.then_some(true) });
            }
        }
    }
    Ok(out)
}

fn pyproject_pins(text: &str) -> Vec<LockedPackage> {
    let mut out = Vec::new();
    let mut section = String::new();
    let mut key = String::new();
    for line in split_lines(text) {
        if let Some(header) = re!(r"^\s*\[+([^\]]+)\]+").captures(line) {
            section = js_trim(&header[1]).to_string();
            key.clear();
            continue;
        }
        if let Some(k) = re!(r"^\s*([A-Za-z0-9_.-]+)\s*=").captures(line) {
            key = k[1].to_string();
        }
        let dev = section == "dependency-groups" || re!(r"(?:^|[._-])(?:dev|test|tests|lint|docs)(?:$|[._-])").is_match(&format!("{section}.{key}"));
        for m in re!(r#"["']([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([^\s;"',=*]+)["';,\s]"#).captures_iter(line) {
            if plain_version(&m[2]) {
                out.push(LockedPackage { ecosystem: "PyPI".to_string(), name: m[1].to_string(), version: m[2].to_string(), dev: dev.then_some(true) });
            }
        }
    }
    out
}

/// What one repo file says the repo runs. `siblings` are the repo's other file
/// paths (at least the same directory's): a package.json's exact pins count
/// only without an npm lockfile beside it, pyproject pins only without
/// uv.lock/poetry.lock, go.sum only without go.mod (go.mod lists the selected
/// versions; go.sum also every version ever considered), app.json only with a Procfile.
pub fn parse_repo_file(path: &str, text: &str, siblings: &[String]) -> Vec<RepoFinding> {
    let kind = if is_vendored(path) { None } else { file_type(path) };
    let base = base_of(path);
    let dir = dir_of(path);
    let beside = |names: &[&str]| siblings.iter().any(|s| s != path && dir_of(s) == dir && names.contains(&base_of(s)));
    let packages = |list: Vec<LockedPackage>| -> Vec<RepoFinding> {
        list.into_iter()
            .map(|p| RepoFinding { kind: RepoFindingKind::Package, ecosystem: Some(p.ecosystem), name: p.name, version: p.version, dev: p.dev })
            .collect()
    };
    let images = |list: Vec<String>| -> Vec<RepoFinding> { list.iter().flat_map(|image| image_findings(image)).collect() };
    let out: Vec<RepoFinding> = match kind {
        Some(FileType::Lock) if base == "go.sum" && beside(&["go.mod"]) => Vec::new(),
        Some(FileType::Lock) => packages(parse_lockfile(path, text)).into_iter().chain(lock_runtimes(base, text)).collect(),
        // An unreadable file contributes nothing; the next refresh retries.
        Some(FileType::PackageJson) if beside(&NPM_LOCKS) => Vec::new(),
        Some(FileType::PackageJson) => exact_pins(text).map(packages).unwrap_or_default(),
        Some(FileType::Pyproject) if beside(&["uv.lock", "poetry.lock"]) => Vec::new(),
        Some(FileType::Pyproject) => packages(pyproject_pins(text)),
        Some(FileType::Dockerfile) => images(dockerfile_images(text)),
        Some(FileType::Compose) => images(compose_images(text)),
        Some(FileType::Version) => runtime_file(base, text),
        Some(FileType::Platform) => platform_of(path, siblings).map(|name| finding(RepoFindingKind::Platform, name, "-")).into_iter().collect(),
        None => Vec::new(),
    };
    let mut seen = HashSet::new();
    out.into_iter()
        .filter(|f| {
            let key = format!(
                "{}\0{}\0{}\0{}\0{}",
                f.kind.as_str(),
                f.ecosystem.as_deref().unwrap_or(""),
                f.name,
                f.version,
                if f.dev == Some(true) { "true" } else { "" }
            );
            seen.insert(key)
        })
        .collect()
}
