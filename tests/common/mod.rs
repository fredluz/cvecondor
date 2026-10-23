// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! A fixture inventory shaped like a small real setup (two GitHub repos, a VPS
//! with three containers), a config on a temp state dir, and a network double.

#![allow(dead_code)]

use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use anyhow::Result;
use cvecondor::config::{Config, Env, build_config};
use cvecondor::feeds::SourceDef;
use cvecondor::http::{Fetch, Request, Response};
use cvecondor::notify::{Notice, Notifier, SendResult};
use cvecondor::types::Inventory;
use indexmap::IndexMap;
use serde::Serialize;
use serde_json::{Value, json};

/// A directory under the system temp dir, removed when dropped.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(prefix: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
        let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).expect("creates the temp dir");
        Self(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The fixture inventory: a WordPress site, an API on Node and a Python worker on GitHub; a VPS running them.
pub fn inventory() -> Inventory {
    serde_json::from_value(json!({
        "collectedAt": "2026-10-21T06:00:00.000Z",
        "sources": {},
        "items": [
            // GitHub: a WordPress site built on the official image, an API on Node, a Python worker.
            { "host": "github", "where": "repo:acme/blog", "kind": "image", "name": "wordpress", "version": "6.8.3-php8.3-apache", "path": "docker-compose.yml" },
            { "host": "github", "where": "repo:acme/blog", "kind": "runtime", "name": "php", "version": "8.3", "path": "docker-compose.yml" },
            { "host": "github", "where": "repo:acme/api", "kind": "runtime", "name": "node", "version": "22.21.0", "path": "Dockerfile" },
            { "host": "github", "where": "repo:acme/api", "kind": "package", "ecosystem": "npm", "name": "left-pad", "version": "1.0.0", "path": "package-lock.json" },
            { "host": "github", "where": "repo:acme/api", "kind": "package", "ecosystem": "npm", "name": "right-pad", "version": "2.0.0", "path": "package-lock.json" },
            { "host": "github", "where": "repo:acme/api", "kind": "platform", "name": "railway", "version": "-", "path": "railway.json" },
            { "host": "github", "where": "repo:acme/worker", "kind": "package", "ecosystem": "PyPI", "name": "certifi", "version": "2026.1.4", "path": "uv.lock" },
            { "host": "github", "where": "repo:acme/worker", "kind": "runtime", "name": "python", "version": "3.12.7", "path": ".python-version" },
            // The VPS: host packages and runtimes, and its containers.
            { "host": "web1", "where": "host", "kind": "os", "name": "Ubuntu 24.04.3 LTS", "version": "24.04" },
            { "host": "web1", "where": "host", "kind": "os-package", "ecosystem": "Ubuntu:24.04:LTS", "name": "vim", "version": "2:9.1.0016-1ubuntu7" },
            { "host": "web1", "where": "host", "kind": "runtime", "name": "node", "version": "20.19.6", "path": "/usr/bin/node" },
            { "host": "web1", "where": "container:blog-wordpress-1", "kind": "runtime", "name": "php", "version": "8.3.28", "running": true },
            { "host": "web1", "where": "container:blog-wordpress-1", "kind": "image", "name": "wordpress", "version": "latest", "running": true },
            { "host": "web1", "where": "container:api", "kind": "runtime", "name": "node", "version": "22.23.2", "running": true },
            { "host": "web1", "where": "container:old-shop", "kind": "runtime", "name": "php", "version": "8.2.20", "running": false }
        ],
        "services": [
            { "host": "web1", "where": "container:blog-wordpress-1", "state": "running", "exposed": ["blog.example.com"] },
            { "host": "web1", "where": "container:api", "state": "running", "exposed": ["api.example.com"] },
            { "host": "web1", "where": "container:old-shop", "state": "exited", "exposed": [] }
        ],
        "secrets": [
            { "host": "web1", "where": "container:api", "location": "env", "kind": "env-var", "name": "OPENAI_API_KEY", "fingerprint": "1a2b3c4d", "exposure": "container-env", "risk": "readable via Docker", "providers": ["openai"] },
            { "host": "github", "where": "repo:acme/api", "location": "actions", "kind": "actions-secret", "name": "RAILWAY_TOKEN", "exposure": "ci-secret", "risk": "CI secret", "providers": ["railway"] }
        ],
        "signals": [
            { "host": "github", "where": "repo:acme/api", "kind": "file", "value": "railway.json" },
            { "host": "github", "where": "repo:acme/api", "kind": "env", "value": "DATABASE_URL", "path": ".env.example" },
            { "host": "github", "where": "repo:acme/api", "kind": "env", "value": "STRIPE_SECRET_KEY", "path": ".env.example" }
        ]
    }))
    .expect("the fixture inventory parses")
}

/// A config whose state dir is a fresh temp dir; the dir goes when this is dropped.
pub struct TestConfig {
    pub config: Config,
    pub dir: TempDir,
}

impl Deref for TestConfig {
    type Target = Config;

    fn deref(&self) -> &Config {
        &self.config
    }
}

/// The defaults of the TS `testConfig`: one GitHub collector, `api.example.com` as priority, news on, no
/// classifier. `extra` is a JSON object whose keys replace or add to them.
pub fn test_config(extra: Value) -> TestConfig {
    let dir = TempDir::new("cvecondor-test");
    let mut raw = json!({
        "stateDir": dir.path(),
        "collectors": [{ "type": "github", "token": "ghp_unused" }],
        "priority": ["api.example.com"],
        "news": true,
        "classifier": false
    });
    if let Value::Object(extra) = extra {
        raw.as_object_mut().expect("an object").extend(extra);
    }
    let config = build_config(&raw, &dir.path().join("config.json"), &Env::new()).expect("the test config builds");
    TestConfig { config, dir }
}

/// An OSV query result as `/v1/querybatch` returns it.
#[derive(Debug, Clone, Serialize)]
pub struct OsvStub {
    pub id: String,
    pub modified: String,
}

/// What the network double serves. Everything not listed answers 304.
#[derive(Debug, Clone, Default)]
pub struct Net {
    /// Bodies served for feed URLs (by source id, or by URL for an unlisted feed); every other feed answers 304.
    pub feeds: IndexMap<String, String>,
    /// Package name → the vulnerabilities `/v1/querybatch` reports for it.
    pub osv: IndexMap<String, Vec<OsvStub>>,
    /// Vulnerability id → the record `/v1/vulns/<id>` returns.
    pub records: IndexMap<String, Value>,
    /// The newest modified time an OSV `modified_id.csv` reports.
    pub osv_head: String,
    /// Extra routes: URL prefix → response body (JSON).
    pub routes: Vec<(String, Value)>,
}

impl Net {
    pub fn new(osv_head: &str) -> Self {
        Self { osv_head: osv_head.to_string(), ..Self::default() }
    }
}

/// A `Net` the test keeps editing while the fetcher serves it (the TS tests mutate `net` between cycles).
pub type SharedNet = Arc<Mutex<Net>>;

pub fn shared(net: Net) -> SharedNet {
    Arc::new(Mutex::new(net))
}

fn reply(status: u16, body: impl Into<Vec<u8>>) -> Result<Response> {
    Ok(Response { status, headers: Vec::new(), body: body.into() })
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        if bytes[i] == b'%' && i + 2 < bytes.len() && hex(bytes[i + 1]).is_some() && hex(bytes[i + 2]).is_some() {
            out.push((hex(bytes[i + 1]).unwrap_or(0) * 16 + hex(bytes[i + 2]).unwrap_or(0)) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The network double: feed URLs of `sources` serve `net.feeds[source id]`, OSV answers from `net.osv` and
/// `net.records`, `routes` match by URL prefix, everything else is a 304.
pub fn network(net: &SharedNet, sources: &[SourceDef]) -> impl Fetch + use<> {
    let net = Arc::clone(net);
    let sources = sources.to_vec();
    move |req: Request| -> Result<Response> {
        let net = net.lock().unwrap_or_else(PoisonError::into_inner);
        let url = req.url.as_str();
        let source_id = sources.iter().find(|s| s.url == url).map(|s| s.id.as_str()).or_else(|| net.feeds.contains_key(url).then_some(url));
        if let Some(body) = source_id.and_then(|id| net.feeds.get(id)) {
            return reply(200, body.as_str());
        }
        if url.ends_with("/modified_id.csv") {
            return reply(206, format!("{},X\n", net.osv_head));
        }
        if url == "https://api.osv.dev/v1/querybatch" {
            let body: Value = serde_json::from_slice(req.body.as_deref().unwrap_or_default())?;
            let results: Vec<Value> = body["queries"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_default()
                .iter()
                .map(|q| json!({ "vulns": q["package"]["name"].as_str().and_then(|n| net.osv.get(n)).cloned().unwrap_or_default() }))
                .collect();
            return reply(200, serde_json::to_vec(&json!({ "results": results }))?);
        }
        if let Some(at) = url.find("/v1/vulns/") {
            let id = percent_decode(&url[at + "/v1/vulns/".len()..]);
            if let Some(record) = net.records.get(&id) {
                return reply(200, serde_json::to_vec(record)?);
            }
        }
        if let Some((_, body)) = net.routes.iter().find(|(prefix, _)| url.starts_with(prefix.as_str())) {
            return reply(200, serde_json::to_vec(body)?);
        }
        reply(304, Vec::new())
    }
}

/// Collects the notices a cycle or a response sends; `notifier()` is what to pass as `notify`.
#[derive(Clone, Default)]
pub struct Recorder {
    notices: Arc<Mutex<Vec<Notice>>>,
}

impl Recorder {
    pub fn notifier(&self) -> Notifier {
        let notices = Arc::clone(&self.notices);
        Arc::new(move |notice: &Notice| {
            notices.lock().unwrap_or_else(PoisonError::into_inner).push(notice.clone());
            SendResult { sent: vec!["test".to_string()], errors: Vec::new() }
        })
    }

    pub fn notices(&self) -> Vec<Notice> {
        self.notices.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }
}

pub fn recorder() -> Recorder {
    Recorder::default()
}

pub struct RssItem<'a> {
    pub guid: &'a str,
    pub title: &'a str,
    pub description: &'a str,
}

/// An RSS feed with the given items.
pub fn rss(items: &[RssItem]) -> String {
    let items: String = items
        .iter()
        .map(|i| {
            format!(
                "<item><title>{}</title><link>https://example.org/{}</link><guid>{}</guid><description>{}</description></item>",
                i.title, i.guid, i.guid, i.description
            )
        })
        .collect();
    format!("<rss><channel>{items}</channel></rss>")
}

/// The text of a file under `tests/fixtures/`.
pub fn fixture(name: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join(name)).unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}
