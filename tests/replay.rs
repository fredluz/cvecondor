// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! The incidents of Oct 14-22 2026, replayed from the documents their sources
//! published, against the fixture inventory: each must open a case that names
//! every affected place, with no classifier key (plain name matching).

mod common;

use anyhow::Result;
use common::{fixture, inventory, recorder, test_config};
use cvecondor::feeds::{FeedState, NEWS_SOURCES, SOURCES};
use cvecondor::http::{Request, Response};
use cvecondor::state::{read_state, write_state};
use cvecondor::types::Inventory;
use cvecondor::util::parse_time;
use cvecondor::watch::{Case, CaseState, CycleDeps, Known, run_cycle};
use indexmap::IndexMap;
use regex::Regex;
use serde_json::json;

fn replay(source_id: &str, body: &str, inventory: &Inventory) -> Vec<Case> {
    let config = test_config(json!({}));
    let at = "2026-10-21T20:00:00.000Z";
    write_state(&config.state_dir, "inventory.json", inventory).expect("writes the inventory");
    // Every other source was just polled and OSV just queried: only the replayed document is new.
    let mut feeds: IndexMap<String, FeedState> = SOURCES
        .iter()
        .chain(NEWS_SOURCES.iter())
        .map(|s| {
            let state =
                FeedState { polled_at: Some(at.into()), ok_at: Some(at.into()), baselined: Some(true), cursor: Some("9999".into()), ..FeedState::default() };
            (s.id.clone(), state)
        })
        .collect();
    feeds.insert(source_id.into(), FeedState { baselined: Some(true), seen: Some(IndexMap::new()), ..FeedState::default() });
    write_state(&config.state_dir, "feeds.json", &feeds).expect("writes the feeds");
    let known = Known {
        osv: IndexMap::new(),
        osv_queried_at: ["npm", "PyPI", "Ubuntu"].iter().map(|f| ((*f).to_string(), at.to_string())).collect(),
        node_index: Some(Vec::new()),
        secrets: Some(Vec::new()),
    };
    write_state(&config.state_dir, "known.json", &known).expect("writes known");
    let url = SOURCES.iter().find(|s| s.id == source_id).expect("a known source").url.clone();
    let fetch = move |req: Request| -> Result<Response> {
        if req.url == url {
            Ok(Response { status: 200, headers: Vec::new(), body: body.as_bytes().to_vec() })
        } else {
            Ok(Response { status: 304, headers: Vec::new(), body: Vec::new() })
        }
    };
    let now = || parse_time("2026-10-21T20:06:00Z").expect("a time");
    let deps = CycleDeps { fetch: &fetch, now: &now, judge: None, judge_vendor: None, respond: None, notify: recorder().notifier(), log: &|_| {} };
    run_cycle(&config, &deps).expect("the cycle runs");
    read_state::<IndexMap<String, Case>>(&config.state_dir, "cases.json").unwrap_or_default().into_values().collect()
}

fn sorted(mut targets: Vec<String>) -> Vec<String> {
    targets.sort();
    targets
}

#[test]
fn cert_eu_2026_018_php_oct_21_every_php_in_use_running_or_not_cisco_ignored() {
    let cases = replay("cert-eu", &fixture("cert-eu-2026-10-21.xml"), &inventory());
    assert_eq!(cases.len(), 1);
    let c = &cases[0];
    assert_eq!(c.title, "2026-018: Critical Vulnerabilities in PHP");
    assert_eq!(c.state, CaseState::Handled);
    assert!(c.fix_available, "the advisory names the fixed releases");
    assert_eq!(
        sorted(c.targets.clone()),
        [
            "github repo:acme/blog php 8.3 (docker-compose.yml)",
            "web1 container:blog-wordpress-1 php 8.3.28 exposed: blog.example.com",
            "web1 container:old-shop php 8.2.20 (stopped)"
        ]
    );
}

#[test]
fn node_js_security_releases_oct_21_every_node_in_repos_on_the_host_and_in_containers() {
    let cases = replay("node-security-blog", &fixture("node-vulnerability-2026-10-21.xml"), &inventory());
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0].title, "Wednesday, October 21, 2026 Security Releases");
    assert_eq!(
        sorted(cases[0].targets.clone()),
        ["github repo:acme/api node 22.21.0 (Dockerfile)", "web1 container:api node 22.23.2 exposed: api.example.com [priority]", "web1 host node 20.19.6"]
    );
    assert_eq!(cases[0].priority, Some(true));
}

#[test]
fn node_js_release_post_fix_available_on_release_day_not_when_posted_a_week_ahead_under_the_same_title() {
    // The October item alone (the feed's July post is long released).
    let post = fixture("node-vulnerability-2026-10-21.xml");
    let july = Regex::new(r"(?s)<item>\s*<title><!\[CDATA\[Wednesday, July.*?</item>").expect("a valid pattern");
    let october = july.replace(&post, "").into_owned();
    let released = replay("node-security-blog", &october, &inventory());
    assert!(released[0].fix_available);
    let ahead = replay("node-security-blog", &october.replacen("Wed, 21 Oct 2026 22:00:00 GMT", "Wed, 14 Oct 2026 18:00:00 GMT", 1), &inventory());
    assert!(!ahead[0].fix_available);
}

#[test]
fn emudhra_intermediate_key_compromise_bugzilla_2083449_oct_18_every_tls_client_trust_store() {
    let cases = replay("ca-incidents", &fixture("bugzilla-ca-2083449.json"), &inventory());
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0].title, "CA incident: eMudhra: Private key compromise of Intermediate Certificates");
    assert_eq!(
        sorted(cases[0].targets.clone()),
        [
            "github repo:acme/api node 22.21.0 (Dockerfile)",
            "github repo:acme/worker certifi 2026.1.4 (uv.lock)",
            "github repo:acme/worker python 3.12.7 (.python-version)",
            "web1 container:api node 22.23.2 exposed: api.example.com [priority]",
            "web1 host node 20.19.6"
        ]
    );
}

#[test]
fn nginx_1_30_6_1_31_7_security_releases_nginx_org_oct_14_nginx_inside_nginx_proxy_fix_named() {
    let mut inv = inventory();
    inv.items.push(
        serde_json::from_value(
            json!({ "host": "github", "where": "repo:acme/edge", "kind": "image", "name": "nginx-proxy", "version": "1.11.6", "path": "docker-compose.yml" }),
        )
        .expect("an item"),
    );
    let cases = replay("nginx-news", &fixture("nginx-news-2026-10-14.xml"), &inv);
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0].targets, ["github repo:acme/edge nginx-proxy 1.11.6 (docker-compose.yml)"]);
    assert_eq!(sorted(cases[0].aliases.clone()), ["CVE-2026-15176", "CVE-2026-93479", "CVE-2026-95101", "CVE-2026-97205", "CVE-2026-97629"]);
    assert!(cases[0].fix_available, "\"released, with fixes for\" names the fixed releases");
}
