// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! The GitHub collector against a fetch double: caching by pushed_at and blob
//! sha, and secret values never leaving the collector.

mod common;

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

use anyhow::Result;
use common::TempDir;
use cvecondor::config::GithubCollector;
use cvecondor::http::{Request, Response};
use cvecondor::inventory::CollectContext;
use cvecondor::inventory::github::collect_github;
use cvecondor::secrets::{Exposure, gitleaks_available};
use cvecondor::util::{base64_encode, sha256_hex};
use serde_json::{Value, json};

/// Built at runtime so this file holds no secret-shaped literal.
fn random(n: usize) -> String {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
    let mut seed = format!("{}-{nanos}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst));
    let mut out = String::new();
    while out.len() < n {
        let digest = sha256_hex(seed.as_bytes());
        out.extend(base64_encode(digest.as_bytes()).chars().filter(char::is_ascii_alphanumeric));
        seed = digest;
    }
    out.truncate(n);
    out
}

/// A git-style object id for a text (any stable 40 hex digits will do).
fn sha(text: &str) -> String {
    sha256_hex(text.as_bytes())[..40].to_string()
}

fn json_response(body: Value, status: u16) -> Response {
    Response { status, headers: vec![("content-type".into(), "application/json".into())], body: body.to_string().into_bytes() }
}

fn config(token: &str) -> GithubCollector {
    GithubCollector {
        name: "github".into(),
        token: token.into(),
        api_url: "https://api.github.com".into(),
        repos: vec![],
        exclude: vec![],
        include_forks: false,
        include_archived: false,
        max_file_bytes: 1_000_000,
    }
}

fn path_of(url: &str) -> String {
    let rest = url.strip_prefix("https://api.github.com").unwrap_or(url);
    rest.split('?').next().unwrap_or(rest).to_string()
}

#[test]
fn collects_items_secrets_and_signals_unchanged_repos_and_blobs_are_not_refetched_no_value_leaks() {
    let dir = TempDir::new("cvecondor-github");
    let token = format!("ghp_{}", random(36));
    let openai = format!("sk-proj-{}", random(40));
    let (db_password, example_value, committed_pat) = (random(20), random(24), format!("ghp_{}", random(36)));
    let files: Vec<(&str, String)> = vec![
        ("Dockerfile", "FROM node:22.21.0-alpine\n".into()),
        (".env", format!("OPENAI_API_KEY={openai}\nDATABASE_URL=postgres://app:{db_password}@db.abcd.supabase.co:5432/app\n")),
        (".env.example", format!("STRIPE_SECRET_KEY={example_value}\nAPP_NAME=x\n")),
        (
            "docker-compose.yml",
            "services:\n  app:\n    build: .\n    environment:\n      - RESEND_API_KEY=${RESEND_API_KEY}\n      - NODE_ENV=production\n".into(),
        ),
        (
            ".github/workflows/ci.yml",
            "jobs:\n  test:\n    steps:\n      - run: npm publish\n        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n".into(),
        ),
        ("config/deploy.yml", format!("github_token: {committed_pat}\n")),
        ("vercel.json", "{}".into()),
        ("README.md", format!("token {}\n", random(30))),
    ];
    let pushed_at = Mutex::new("2026-10-01T00:00:00Z".to_string());
    let requests: Mutex<Vec<String>> = Mutex::new(Vec::new());

    let fetch = |req: Request| -> Result<Response> {
        // The token goes to the GitHub API only, never to a registry.
        assert_eq!(
            req.url.starts_with("https://api.github.com"),
            req.headers.iter().any(|(k, v)| k == "Authorization" && *v == format!("Bearer {token}")),
            "{}",
            req.url
        );
        let path = path_of(&req.url);
        requests.lock().unwrap_or_else(PoisonError::into_inner).push(path.clone());
        let repo = json!({ "full_name": "acme/app", "private": false, "fork": false, "archived": false,
            "pushed_at": pushed_at.lock().unwrap_or_else(PoisonError::into_inner).clone(), "default_branch": "main" });
        if path == "/user/repos" {
            return Ok(json_response(
                json!([repo, { "full_name": "acme/old-fork", "private": false, "fork": true, "archived": false, "pushed_at": "2026-10-01T00:00:00Z", "default_branch": "main" }]),
                200,
            ));
        }
        if path == "/repos/acme/app/git/trees/main" {
            let tree: Vec<Value> = files.iter().map(|(p, t)| json!({ "path": p, "type": "blob", "sha": sha(t), "size": t.len() })).collect();
            return Ok(json_response(json!({ "truncated": false, "tree": tree }), 200));
        }
        if let Some(blob) = path.strip_prefix("/repos/acme/app/git/blobs/")
            && let Some((_, text)) = files.iter().find(|(_, t)| sha(t) == blob)
        {
            let encoded = base64_encode(text.as_bytes());
            let wrapped: Vec<&str> = encoded.as_bytes().chunks(60).map(|c| std::str::from_utf8(c).expect("ascii")).collect();
            return Ok(json_response(json!({ "encoding": "base64", "content": wrapped.join("\n") }), 200));
        }
        if path == "/repos/acme/app/actions/secrets" {
            return Ok(json_response(json!({ "message": "Resource not accessible by integration" }), 403));
        }
        if path == "/repos/acme/app/deployments" {
            return Ok(json_response(json!([{ "creator": { "login": "vercel[bot]" }, "environment": "Production" }]), 200));
        }
        Ok(json_response(json!({ "message": "Not Found" }), 404))
    };
    let cfg = config(&token);
    let log = |_: &str| {};
    let context = CollectContext { state_dir: dir.path(), fetch: &fetch, log: &log, previous: None };
    let seen = || std::mem::take(&mut *requests.lock().unwrap_or_else(PoisonError::into_inner));

    let first = collect_github(&cfg, &context).expect("first collection");
    let out = serde_json::to_string(&(&first.items, &first.secrets, &first.signals, &first.warnings)).expect("serializes");
    let cache = std::fs::read_to_string(dir.path().join("github.cache.json")).expect("cache written");
    for value in [&token, &openai, &db_password, &example_value, &committed_pat] {
        assert!(!out.contains(value.as_str()), "a secret value in the result");
        assert!(!cache.contains(value.as_str()), "a secret value in the cache");
    }
    assert!(!seen().iter().any(|path| path.contains("old-fork")));
    assert!(first.items.iter().any(|i| i.r#where == "repo:acme/app"
        && i.kind.as_str() == "runtime"
        && i.name == "node"
        && i.version == "22.21.0"
        && i.path.as_deref() == Some("Dockerfile")));
    assert!(first.items.iter().any(|i| i.kind.as_str() == "platform" && i.name == "vercel"));

    let env: Vec<_> = first.secrets.iter().filter(|s| s.location == ".env").collect();
    assert!(env.len() >= 2 && env.iter().all(|s| s.exposure == Exposure::CommittedEnvFile));
    assert!(env.iter().any(|s| s.name.as_deref() == Some("OPENAI_API_KEY")
        && s.line == Some(1)
        && s.fingerprint.as_deref().is_some_and(|f| f.len() == 8 && f.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()))
        && s.providers.iter().any(|p| p == "openai")));
    assert!(env[0].risk.contains("anyone on the internet"));
    if gitleaks_available() {
        assert!(first.secrets.iter().any(|s| s.location == "config/deploy.yml" && s.exposure == Exposure::RepoFile && s.line == Some(1) && s.commit.is_none()));
    }

    let signals: HashSet<String> =
        first.signals.iter().map(|s| format!("{} {}", serde_json::to_value(s.kind).expect("kind").as_str().unwrap_or(""), s.value)).collect();
    for expected in [
        "env STRIPE_SECRET_KEY",
        "env RESEND_API_KEY",
        "env NPM_TOKEN",
        "env NODE_AUTH_TOKEN",
        "deployment vercel[bot]",
        "deployment Production",
        "hostname supabase.co",
        "file vercel.json",
    ] {
        assert!(signals.contains(expected), "{expected}");
    }

    seen();
    let second = collect_github(&cfg, &context).expect("second collection");
    assert_eq!(seen(), vec!["/user/repos".to_string()]);
    assert_eq!(second.items, first.items);
    assert_eq!(second.secrets, first.secrets);
    assert_eq!(second.signals, first.signals);
    assert_eq!(second.warnings, first.warnings);

    // Pushed again with the same files: a new tree, no blob refetched.
    *pushed_at.lock().unwrap_or_else(PoisonError::into_inner) = "2026-10-02T00:00:00Z".to_string();
    let third = collect_github(&cfg, &context).expect("third collection");
    let requested = seen();
    assert!(requested.iter().any(|p| p == "/repos/acme/app/git/trees/main"));
    assert!(!requested.iter().any(|p| p.contains("/git/blobs/")));
    assert_eq!(third.secrets, first.secrets);
}

#[test]
fn compose_literals_are_secrets_but_block_scalars_and_anchors_are_not() {
    let dir = TempDir::new("cvecondor-github");
    let password = random(20);
    let block = random(20);
    let compose = format!("services:\n  db:\n    environment:\n      DB_PASSWORD: {password}\n      SECRET_TOKEN: >{block}\n");
    let fetch = |req: Request| -> Result<Response> {
        let path = path_of(&req.url);
        Ok(match path.as_str() {
            "/user/repos" => {
                json_response(json!([{ "full_name": "acme/db", "private": true, "pushed_at": "2026-10-01T00:00:00Z", "default_branch": "main" }]), 200)
            }
            "/repos/acme/db/git/trees/main" => {
                json_response(json!({ "tree": [{ "path": "compose.yaml", "type": "blob", "sha": sha(&compose), "size": compose.len() }] }), 200)
            }
            p if p == format!("/repos/acme/db/git/blobs/{}", sha(&compose)) => {
                json_response(json!({ "encoding": "base64", "content": base64_encode(compose.as_bytes()) }), 200)
            }
            _ => json_response(json!({ "message": "Not Found" }), 404),
        })
    };
    let log = |_: &str| {};
    let context = CollectContext { state_dir: dir.path(), fetch: &fetch, log: &log, previous: None };
    let collected = collect_github(&config("token"), &context).expect("collects");
    let compose_secrets: Vec<_> = collected.secrets.iter().filter(|s| s.location == "compose.yaml" && s.kind == "env-var").collect();
    assert!(compose_secrets.iter().any(|s| s.name.as_deref() == Some("DB_PASSWORD") && s.line == Some(4)));
    assert!(!compose_secrets.iter().any(|s| s.name.as_deref() == Some("SECRET_TOKEN")));
    assert!(collected.secrets.iter().all(|s| s.risk.contains("private repo")));
    let out = serde_json::to_string(&collected.secrets).expect("serializes");
    assert!(!out.contains(&password) && !out.contains(&block));
}

#[test]
fn rate_limit_keeps_previous_results_and_names_the_reset() {
    let dir = TempDir::new("cvecondor-github");
    let limited = Mutex::new(false);
    let fetch = |req: Request| -> Result<Response> {
        let path = path_of(&req.url);
        let repo = json!([{ "full_name": "acme/app", "private": false, "pushed_at": "2026-10-01T00:00:00Z", "default_branch": "main" }]);
        if *limited.lock().unwrap_or_else(PoisonError::into_inner) {
            if path == "/user/repos" {
                return Ok(json_response(
                    json!([{ "full_name": "acme/app", "private": false, "pushed_at": "2026-10-02T00:00:00Z", "default_branch": "main" }]),
                    200,
                ));
            }
            return Ok(Response {
                status: 403,
                headers: vec![("x-ratelimit-remaining".into(), "0".into()), ("x-ratelimit-reset".into(), "1790000000".into())],
                body: b"{}".to_vec(),
            });
        }
        Ok(match path.as_str() {
            "/user/repos" => json_response(repo, 200),
            "/repos/acme/app/git/trees/main" => {
                json_response(json!({ "tree": [{ "path": "Dockerfile", "type": "blob", "sha": sha("FROM node:22.21.0\n"), "size": 17 }] }), 200)
            }
            p if p.starts_with("/repos/acme/app/git/blobs/") => {
                json_response(json!({ "encoding": "base64", "content": base64_encode(b"FROM node:22.21.0\n") }), 200)
            }
            _ => json_response(json!({}), 404),
        })
    };
    let log = |_: &str| {};
    let context = CollectContext { state_dir: dir.path(), fetch: &fetch, log: &log, previous: None };
    let cfg = config("token");
    let first = collect_github(&cfg, &context).expect("first collection");
    assert!(first.items.iter().any(|i| i.name == "node"));

    *limited.lock().unwrap_or_else(PoisonError::into_inner) = true;
    let second = collect_github(&cfg, &context).expect("kept");
    assert_eq!(second.items, first.items);
    assert!(
        second
            .warnings
            .iter()
            .any(|w| w == "GitHub API rate limit reached (resets 2026-09-21T14:13:20.000Z): 1 repos not refreshed, their previous results kept"),
        "{:?}",
        second.warnings
    );

    // Nothing cached to fall back on: the collector fails.
    let other = TempDir::new("cvecondor-github");
    let context = CollectContext { state_dir: other.path(), fetch: &fetch, log: &log, previous: None };
    let error = collect_github(&cfg, &context).expect_err("no repos collected");
    assert_eq!(error.to_string(), "GitHub API rate limit reached (resets 2026-09-21T14:13:20.000Z): no repos collected");
}

#[test]
fn a_bundling_image_gives_the_server_version_from_its_registry_env_once_a_day() {
    let dir = TempDir::new("cvecondor-github");
    let compose = "services:\n  proxy:\n    image: nginxproxy/nginx-proxy:1.6\n    ports:\n      - 80:80\n  build-only:\n    image: scratch\n";
    let registry: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let pushed_at = Mutex::new("2026-10-01T00:00:00Z".to_string());
    let fetch = |req: Request| -> Result<Response> {
        if let Some(rest) = req.url.strip_prefix("https://registry-1.docker.io/v2/") {
            registry.lock().unwrap_or_else(PoisonError::into_inner).push(rest.to_string());
            return Ok(match rest {
                "nginxproxy/nginx-proxy/manifests/1.6" => json_response(json!({ "config": { "digest": "sha256:cfg" } }), 200),
                "nginxproxy/nginx-proxy/blobs/sha256:cfg" => {
                    json_response(json!({ "config": { "Env": ["PATH=/usr/bin", "NGINX_VERSION=1.27.2", "DOCKER_HOST=unix:///tmp/docker.sock"] } }), 200)
                }
                _ => json_response(json!({}), 404),
            });
        }
        let path = path_of(&req.url);
        Ok(match path.as_str() {
            "/user/repos" => json_response(
                json!([{ "full_name": "acme/edge", "private": true, "pushed_at": pushed_at.lock().unwrap_or_else(PoisonError::into_inner).clone(), "default_branch": "main" }]),
                200,
            ),
            "/repos/acme/edge/git/trees/main" => {
                json_response(json!({ "tree": [{ "path": "docker-compose.yml", "type": "blob", "sha": sha(compose), "size": compose.len() }] }), 200)
            }
            p if p == format!("/repos/acme/edge/git/blobs/{}", sha(compose)) => {
                json_response(json!({ "encoding": "base64", "content": base64_encode(compose.as_bytes()) }), 200)
            }
            _ => json_response(json!({ "message": "Not Found" }), 404),
        })
    };
    let log = |_: &str| {};
    let context = CollectContext { state_dir: dir.path(), fetch: &fetch, log: &log, previous: None };
    let cfg = config("token");

    let first = collect_github(&cfg, &context).expect("first collection");
    let nginx: Vec<_> = first.items.iter().filter(|i| i.kind.as_str() == "runtime" && i.name == "nginx").collect();
    assert_eq!(nginx.len(), 1, "{:?}", first.items);
    assert_eq!((nginx[0].version.as_str(), nginx[0].r#where.as_str(), nginx[0].path.as_deref()), ("1.27.2", "repo:acme/edge", Some("docker-compose.yml")));
    assert!(first.items.iter().any(|i| i.kind.as_str() == "image" && i.name == "nginx-proxy" && i.version == "1.6"));
    assert!(first.warnings.iter().all(|w| !w.contains("nginx-proxy")), "{:?}", first.warnings);
    let cache = std::fs::read_to_string(dir.path().join("github.cache.json")).expect("cache written");
    assert!(!cache.contains("DOCKER_HOST") && !cache.contains("/usr/bin"), "only version variables are cached");

    registry.lock().unwrap_or_else(PoisonError::into_inner).clear();
    // Pushed again (a new tree, the same file): the image was read less than 24 hours ago.
    *pushed_at.lock().unwrap_or_else(PoisonError::into_inner) = "2026-10-02T00:00:00Z".to_string();
    let second = collect_github(&cfg, &context).expect("second collection");
    assert!(registry.lock().unwrap_or_else(PoisonError::into_inner).is_empty(), "no registry request inside 24 hours");
    assert_eq!(second.items, first.items);
}
