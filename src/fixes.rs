// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! What an open case is waiting for, checked every cycle: a package release, an
//! image rebuilt on a fixed runtime, or OSV naming a fixed version. When it
//! ships, the case reopens so the responder applies it and removes the workaround.

use std::cmp::Ordering;
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::http::{Fetch, Request, Response};
use crate::name::{NAME, USER_AGENT};
use crate::versions::compare_loose;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitPackage {
    pub ecosystem: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", rename_all_fields = "camelCase")]
pub enum FixWait {
    /// OSV names a fixed version for one of these packages, the ones in use: a Debian:14 fix doesn't count for Debian:12.
    Osv { id: String, packages: Vec<WaitPackage> },
    /// A release at or above `at_least` exists in the registry (npm, PyPI, crates.io, RubyGems, Packagist).
    Package { ecosystem: String, name: String, at_least: String },
    /// The image tag now carries `env` (e.g. PHP_VERSION) at or above `at_least`.
    Image { image: String, env: String, at_least: String },
}

/// Per-request timeout for registry calls.
const TIMEOUT: Duration = Duration::from_secs(30);

pub fn describe_wait(w: &FixWait) -> String {
    match w {
        FixWait::Osv { id, .. } => format!("a fixed version in {id}"),
        FixWait::Package { ecosystem, name, at_least } => format!("{ecosystem} {name} >= {at_least}"),
        FixWait::Image { image, env, at_least } => format!("{image} with {env} >= {at_least}"),
    }
}

/// The fenced ```` ```<NAME>-wait ```` blocks of a report.
static WAIT_BLOCK: LazyLock<Regex> = LazyLock::new(|| Regex::new(&format!(r"(?s)```{}-wait\s*\n(.*?)```", regex::escape(NAME))).expect("valid regex"));

/// Parses the responder's machine-readable waits from its report: a fenced block
/// tagged `<NAME>-wait`, one JSON object per line:
/// `{"package": "npm:next", "atLeast": "15.5.7"}` or `{"image": "wordpress:php8.3-apache", "env": "PHP_VERSION", "atLeast": "8.3.36"}`.
pub fn parse_waits(report: &str) -> Vec<FixWait> {
    let mut out = Vec::new();
    for block in WAIT_BLOCK.captures_iter(report) {
        for line in block[1].split('\n') {
            // Not a wait line: not JSON, not an object, or no atLeast.
            let Ok(Value::Object(v)) = serde_json::from_str::<Value>(line) else { continue };
            let Some(at_least) = v.get("atLeast").and_then(Value::as_str) else { continue };
            let text = |key: &str| v.get(key).and_then(Value::as_str);
            if let Some((ecosystem, name)) = text("package").and_then(|p| p.split_once(':')) {
                out.push(FixWait::Package { ecosystem: ecosystem.to_string(), name: name.to_string(), at_least: at_least.to_string() });
            } else if let (Some(image), Some(env)) = (text("image"), text("env")) {
                out.push(FixWait::Image { image: image.to_string(), env: env.to_string(), at_least: at_least.to_string() });
            }
        }
    }
    out
}

static REVISION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"-r[0-9]+$").expect("valid regex"));

/// The newest plain release (no letters once a leading `v` and a `-rN` revision are gone) at or above `floor`.
fn at_least(versions: &[String], floor: &str) -> Option<String> {
    let mut found: Vec<&String> = versions
        .iter()
        .filter(|v| {
            let bare = v.strip_prefix('v').unwrap_or(v);
            !REVISION.replace(bare, "").chars().any(|c| c.is_ascii_alphabetic()) && compare_loose(v, floor) != Ordering::Less
        })
        .collect();
    found.sort_by(|a, b| compare_loose(a, b));
    found.last().map(|v| (*v).clone())
}

/// JS `encodeURIComponent`.
fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The versions a registry's response lists.
fn registry_versions(ecosystem: &str, name: &str, data: &Value) -> Result<Vec<String>> {
    let keys = |v: Option<&Value>| v.and_then(Value::as_object).map(|o| o.keys().cloned().collect()).unwrap_or_default();
    let field = |items: Option<&Value>, key: &str| -> Vec<String> {
        items.and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.get(key).and_then(Value::as_str).map(str::to_string)).collect()).unwrap_or_default()
    };
    Ok(match ecosystem {
        "npm" => keys(data.get("versions")),
        "PyPI" => keys(data.get("releases")),
        "crates.io" => field(data.get("versions"), "num"),
        "RubyGems" => {
            if !data.is_array() {
                bail!("{ecosystem} {name}: unexpected response");
            }
            field(Some(data), "number")
        }
        _ => field(data.get("packages").and_then(|p| p.get(name)), "version").into_iter().map(|v| v.strip_prefix('v').unwrap_or(&v).to_string()).collect(),
    })
}

/// Looks up the fixed versions OSV names for an `Osv` wait (the caller owns the OSV cache).
pub type OsvFixed<'a> = &'a dyn Fn(&FixWait) -> Result<Vec<String>>;

/// The shipped version that satisfies the wait, or `None` while still waiting.
pub fn check_wait(wait: &FixWait, fetch: &dyn Fetch, osv_fixed: Option<OsvFixed>) -> Result<Option<String>> {
    match wait {
        FixWait::Osv { .. } => {
            let Some(osv_fixed) = osv_fixed else { return Ok(None) };
            Ok(Some(osv_fixed(wait)?.join(", ")).filter(|s| !s.is_empty()))
        }
        FixWait::Package { ecosystem, name, at_least: floor } => {
            let encoded = encode_uri_component(name);
            let encoded = encoded.strip_prefix("%40").map_or_else(|| encoded.clone(), |rest| format!("@{rest}"));
            let url = match ecosystem.as_str() {
                "npm" => format!("https://registry.npmjs.org/{encoded}"),
                "PyPI" => format!("https://pypi.org/pypi/{encoded}/json"),
                "crates.io" => format!("https://crates.io/api/v1/crates/{encoded}"),
                "RubyGems" => format!("https://rubygems.org/api/v1/versions/{encoded}.json"),
                "Packagist" => format!("https://repo.packagist.org/p2/{name}.json"),
                _ => return Ok(None),
            };
            let mut request = Request::get(url).header("User-Agent", USER_AGENT).timeout(TIMEOUT);
            if ecosystem == "npm" {
                request = request.header("Accept", "application/vnd.npm.install-v1+json");
            }
            let response = fetch.fetch(request)?;
            if !response.ok() {
                bail!("{ecosystem} {name}: HTTP {}", response.status);
            }
            let data: Value = response.json()?;
            Ok(at_least(&registry_versions(ecosystem, name, &data)?, floor))
        }
        FixWait::Image { image, env, at_least } => {
            let vars = image_env(image, fetch)?;
            let prefix = format!("{env}=");
            // An image that doesn't set the variable would leave the case waiting forever, silently.
            let Some(value) = vars.iter().find_map(|e| e.strip_prefix(&prefix)) else {
                bail!("{image} sets no {env}: this wait can never resolve; wait on a package, or on a tag whose image sets {env}");
            };
            Ok((compare_loose(value, at_least) != Ordering::Less).then(|| format!("{image} {env}={value}")))
        }
    }
}

const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json";

/// The `key="value"` field of a `WWW-Authenticate` challenge, or "".
fn challenge_field(challenge: &str, key: &str) -> String {
    let marker = format!("{key}=\"");
    challenge
        .find(&marker)
        .map(|at| &challenge[at + marker.len()..])
        .and_then(|rest| rest.split_once('"'))
        .filter(|(value, _)| !value.is_empty())
        .map_or_else(String::new, |(value, _)| value.to_string())
}

#[derive(Deserialize)]
struct Platform {
    #[serde(default)]
    os: String,
    #[serde(default)]
    architecture: String,
}

#[derive(Deserialize)]
struct ManifestRef {
    digest: String,
    #[serde(default)]
    platform: Option<Platform>,
}

#[derive(Deserialize)]
struct ConfigRef {
    digest: String,
}

/// An image manifest, or an index of them.
#[derive(Deserialize)]
struct Manifest {
    #[serde(default)]
    manifests: Option<Vec<ManifestRef>>,
    #[serde(default)]
    config: Option<ConfigRef>,
}

#[derive(Deserialize)]
struct TokenBody {
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    access_token: Option<String>,
}

#[derive(Deserialize)]
struct ImageConfig {
    #[serde(default)]
    config: Option<ImageConfigInner>,
}

#[derive(Deserialize)]
struct ImageConfigInner {
    #[serde(rename = "Env", default)]
    env: Option<Vec<String>>,
}

/// An image tag's config env (linux/amd64), read from its registry with an anonymous pull token: no pull, no Docker needed.
pub fn image_env(image: &str, fetch: &dyn Fetch) -> Result<Vec<String>> {
    let colon = image.rfind(':');
    let slash = image.rfind('/');
    let tagged = match (colon, slash) {
        (Some(c), Some(s)) => c > s,
        (Some(_), None) => true,
        _ => false,
    };
    let (reference, tag) = match colon.filter(|_| tagged) {
        Some(c) => (&image[..c], &image[c + 1..]),
        None => (image, "latest"),
    };
    let first = reference.split('/').next().unwrap_or("");
    let registry = if reference.contains('/') && first.contains(['.', ':']) { first } else { "registry-1.docker.io" };
    let repo = if registry == "registry-1.docker.io" {
        if reference.contains('/') { reference.to_string() } else { format!("library/{reference}") }
    } else {
        reference[first.len() + 1..].to_string()
    };
    let mut token: Option<String> = None;
    let mut request = |path: &str| -> Result<Response> {
        let url = format!("https://{registry}/v2/{repo}/{path}");
        let build = |token: &Option<String>| {
            let mut req = Request::get(url.as_str()).header("Accept", MANIFEST_ACCEPT).header("User-Agent", USER_AGENT).timeout(TIMEOUT);
            if let Some(token) = token {
                req = req.header("Authorization", format!("Bearer {token}"));
            }
            req
        };
        let mut response = fetch.fetch(build(&token))?;
        if response.status == 401 && token.is_none() {
            let challenge = response.header("www-authenticate").unwrap_or("").to_string();
            let scope = Some(challenge_field(&challenge, "scope")).filter(|s| !s.is_empty()).unwrap_or_else(|| format!("repository:{repo}:pull"));
            let auth_url = format!(
                "{}?service={}&scope={}",
                challenge_field(&challenge, "realm"),
                encode_uri_component(&challenge_field(&challenge, "service")),
                encode_uri_component(&scope)
            );
            let auth = fetch.fetch(Request::get(auth_url).header("User-Agent", USER_AGENT).timeout(TIMEOUT))?;
            if !auth.ok() {
                bail!("{image}: registry token HTTP {}", auth.status);
            }
            let body: TokenBody = auth.json()?;
            let Some(granted) = body.token.or(body.access_token) else { bail!("{image}: registry token response carries no token") };
            token = Some(granted);
            response = fetch.fetch(build(&token))?;
        }
        if !response.ok() {
            bail!("{image}: registry HTTP {}", response.status);
        }
        Ok(response)
    };
    let mut manifest: Manifest = request(&format!("manifests/{tag}"))?.json()?;
    if let Some(manifests) = &manifest.manifests {
        let pick = manifests
            .iter()
            .find(|m| m.platform.as_ref().is_some_and(|p| p.os == "linux" && p.architecture == "amd64"))
            .or_else(|| manifests.first())
            .ok_or_else(|| anyhow!("{image}: empty manifest list"))?;
        manifest = request(&format!("manifests/{}", pick.digest))?.json()?;
    }
    let config = manifest.config.ok_or_else(|| anyhow!("{image}: no image config"))?;
    let config: ImageConfig = request(&format!("blobs/{}", config.digest))?.json().context("reading the image config")?;
    Ok(config.config.and_then(|c| c.env).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use serde_json::json;

    use super::*;

    fn json_response(value: &Value) -> Response {
        Response { status: 200, headers: Vec::new(), body: value.to_string().into_bytes() }
    }

    /// A registry with one single-platform tag whose config sets `env`.
    fn registry(env: &[&str]) -> impl Fetch + use<> {
        let env: Vec<String> = env.iter().map(|e| e.to_string()).collect();
        move |req: Request| {
            Ok(if req.url.contains("/manifests/") {
                json_response(&json!({ "config": { "digest": "sha256:c0" } }))
            } else if req.url.contains("/blobs/") {
                json_response(&json!({ "config": { "Env": env } }))
            } else {
                Response { status: 404, headers: Vec::new(), body: Vec::new() }
            })
        }
    }

    fn image_wait() -> FixWait {
        FixWait::Image { image: "acme/app:1-alpine".into(), env: "APP_VERSION".into(), at_least: "1.4.4".into() }
    }

    #[test]
    fn parse_waits_reads_each_wait_kind_and_skips_other_lines() {
        let report = format!(
            "## Message\nwaiting\n\n```{NAME}-wait\n{{\"package\": \"npm:@acme/next\", \"atLeast\": \"15.5.7\"}}\nnot json\n{{\"image\": \"wordpress:php8.3-apache\", \"env\": \"PHP_VERSION\", \"atLeast\": \"8.3.36\"}}\n{{\"package\": \"npm:left-pad\"}}\n{{\"package\": \"nocolon\", \"atLeast\": \"1\"}}\n{{\"image\": \"x\", \"atLeast\": \"1\"}}\nnull\n```\n\n```json\n{{\"package\": \"npm:other\", \"atLeast\": \"1\"}}\n```\n"
        );
        assert_eq!(
            parse_waits(&report),
            [
                FixWait::Package { ecosystem: "npm".into(), name: "@acme/next".into(), at_least: "15.5.7".into() },
                FixWait::Image { image: "wordpress:php8.3-apache".into(), env: "PHP_VERSION".into(), at_least: "8.3.36".into() },
            ]
        );
        assert_eq!(describe_wait(&parse_waits(&report)[0]), "npm @acme/next >= 15.5.7");
        assert_eq!(describe_wait(&parse_waits(&report)[1]), "wordpress:php8.3-apache with PHP_VERSION >= 8.3.36");
        let osv = FixWait::Osv { id: "CVE-2026-1".into(), packages: vec![WaitPackage { ecosystem: "Debian:12".into(), name: "vim".into() }] };
        assert_eq!(describe_wait(&osv), "a fixed version in CVE-2026-1");
    }

    #[test]
    fn parse_waits_ignores_a_report_without_the_block() {
        assert!(parse_waits("no waits here\n```json\n{\"package\": \"npm:x\", \"atLeast\": \"1\"}\n```").is_empty());
    }

    #[test]
    fn image_wait_resolves_when_the_tag_carries_the_fixed_runtime_and_waits_below_it() {
        assert_eq!(
            check_wait(&image_wait(), &registry(&["PATH=/usr/bin", "APP_VERSION=1.4.4"]), None).expect("checks").as_deref(),
            Some("acme/app:1-alpine APP_VERSION=1.4.4")
        );
        assert_eq!(check_wait(&image_wait(), &registry(&["APP_VERSION=1.4.3"]), None).expect("checks"), None);
    }

    #[test]
    fn image_wait_on_a_variable_the_image_never_sets_fails_loudly() {
        let error = check_wait(&image_wait(), &registry(&["PATH=/usr/bin"]), None).expect_err("never resolves");
        assert!(error.to_string().contains("sets no APP_VERSION: this wait can never resolve"), "{error}");
    }

    #[test]
    fn image_env_takes_an_anonymous_token_and_the_linux_amd64_manifest() {
        let seen: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let fetch = |req: Request| {
            seen.lock().expect("lock").push(req.url.clone());
            let bearer = req.headers.iter().any(|(k, v)| k == "Authorization" && v == "Bearer tok");
            Ok(if req.url.starts_with("https://auth.example.com/token") {
                json_response(&json!({ "token": "tok" }))
            } else if !bearer {
                Response {
                    status: 401,
                    headers: vec![("www-authenticate".into(), "Bearer realm=\"https://auth.example.com/token\",service=\"registry.example.com\"".into())],
                    body: Vec::new(),
                }
            } else if req.url.ends_with("/manifests/9") {
                json_response(&json!({ "manifests": [
                    { "digest": "sha256:arm", "platform": { "os": "linux", "architecture": "arm64" } },
                    { "digest": "sha256:amd", "platform": { "os": "linux", "architecture": "amd64" } }
                ] }))
            } else if req.url.ends_with("/manifests/sha256:amd") {
                json_response(&json!({ "config": { "digest": "sha256:cfg" } }))
            } else if req.url.ends_with("/blobs/sha256:cfg") {
                json_response(&json!({ "config": { "Env": ["APP_VERSION=9.1"] } }))
            } else {
                Response { status: 404, headers: Vec::new(), body: Vec::new() }
            })
        };
        assert_eq!(image_env("registry.example.com:5000/acme/app:9", &fetch).expect("reads"), ["APP_VERSION=9.1"]);
        let seen = seen.lock().expect("lock");
        assert_eq!(seen[0], "https://registry.example.com:5000/v2/acme/app/manifests/9");
        assert_eq!(seen[1], "https://auth.example.com/token?service=registry.example.com&scope=repository%3Aacme%2Fapp%3Apull");
    }

    #[test]
    fn package_wait_picks_the_newest_plain_release_at_or_above_the_floor() {
        let registry = |req: Request| {
            assert_eq!(req.url, "https://registry.npmjs.org/@acme%2Fnext");
            Ok(json_response(&json!({ "versions": { "15.5.6": {}, "15.5.7": {}, "15.6.0-canary.1": {}, "15.5.9": {} } })))
        };
        let wait = |at_least: &str| FixWait::Package { ecosystem: "npm".into(), name: "@acme/next".into(), at_least: at_least.into() };
        assert_eq!(check_wait(&wait("15.5.7"), &registry, None).expect("checks").as_deref(), Some("15.5.9"));
        assert_eq!(check_wait(&wait("15.6.0"), &registry, None).expect("checks"), None);
        let down = |_: Request| Ok(Response { status: 500, headers: Vec::new(), body: Vec::new() });
        assert_eq!(check_wait(&wait("1"), &down, None).expect_err("fails").to_string(), "npm @acme/next: HTTP 500");
    }

    #[test]
    fn osv_wait_resolves_to_what_the_callback_reports() {
        let wait = FixWait::Osv { id: "CVE-2026-1".into(), packages: Vec::new() };
        let never = |_: Request| -> Result<Response> { panic!("OSV waits make no request") };
        let fixed = |_: &FixWait| Ok(vec!["1.2".to_string(), "1.3".to_string()]);
        let none = |_: &FixWait| Ok(Vec::new());
        assert_eq!(check_wait(&wait, &never, Some(&fixed)).expect("checks").as_deref(), Some("1.2, 1.3"));
        assert_eq!(check_wait(&wait, &never, Some(&none)).expect("checks"), None);
        assert_eq!(check_wait(&wait, &never, None).expect("checks"), None);
    }
}
