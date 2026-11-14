// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! `dashboard`: the page for an empty state and for a realistic one, what it escapes and never shows, and that the
//! command (the built binary) writes a private file and leaves the state dir exactly as it was.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use common::{TempDir, inventory};
use cvecondor::config::{Config, Env, NotifyEvent, build_config};
use cvecondor::dashboard::render;
use cvecondor::inbox::keep;
use cvecondor::notify::Notice;
use cvecondor::state::write_state;
use cvecondor::types::Inventory;
use cvecondor::util::parse_time;
use indexmap::IndexMap;
use serde_json::{Value, json};

const XSS_SCRIPT: &str = "<script>alert(1)</script>";
const XSS_IMG: &str = "\"><img src=x onerror=alert(1)>";
/// A value the config reaches through the env (`${DASH_TOKEN}`): it must not show up anywhere in the page.
const TOKEN: &str = "ghp_dashTOKEN0123456789abcdefABCDEF012345";

fn config_in(dir: &Path) -> Config {
    let raw = json!({ "stateDir": dir, "classifier": false, "collectors": [{ "type": "github", "token": "${DASH_TOKEN}" }] });
    let env: Env = [("DASH_TOKEN".to_string(), TOKEN.to_string())].into();
    build_config(&raw, &dir.join("config.json"), &env).expect("the config builds")
}

fn case(key: &str, extra: Value) -> Value {
    let mut raw = json!({
        "key": key, "kind": "vulnerability", "title": "a case", "state": "handled", "reason": "high", "severity": "high", "fixAvailable": false,
        "aliases": [], "urls": [], "sources": [], "targets": [], "places": [{ "host": "github", "where": "repo:acme/api" }],
        "firstSeen": "2026-10-21T07:00:00.000Z", "updatedAt": "2026-10-21T07:00:00.000Z"
    });
    raw.as_object_mut().expect("an object").extend(extra.as_object().expect("an object").clone());
    raw
}

/// A state dir shaped like a watcher that has been running: cycle, feeds, inventory, three cases, inbox, reports.
fn seed(dir: &Path) {
    write_state(dir, "inventory.json", &inventory()).expect("writes the inventory");
    write_state(
        dir,
        "last-cycle.json",
        &json!({ "at": "2026-10-21T08:00:00.000Z", "polled": 12, "fresh": 3, "firstRead": 0, "osvQueried": [], "newCases": [], "dispatched": [], "reopened": [],
                 "secretsTold": 0, "vendors": 2, "errors": [], "durationMs": 840 }),
    )
    .expect("writes the cycle");
    write_state(
        dir,
        "feeds.json",
        &json!({ "cert-eu": { "okAt": "2026-10-21T08:00:00.000Z" }, "nvd": { "error": "HTTP 503", "okAt": "2026-10-20T08:00:00.000Z" } }),
    )
    .expect("writes the feeds");
    let cases: IndexMap<String, Value> = [
        case(
            "CVE-2026-1111",
            json!({
                "title": format!("PHP RCE {XSS_SCRIPT}"), "reason": format!("reaches blog.example.com {XSS_IMG}"), "state": "pending", "status": "open",
                "exploited": true, "priority": true, "updatedAt": "2026-10-21T09:00:00.000Z",
                "assessment": { "rating": "act today", "why": format!("critical and public {XSS_SCRIPT}") },
                "urls": ["https://example.com/advisory?a=1&b=2", "javascript:alert(1)", "https://example.com/\"onmouseover=\"alert(1)"],
                "affected": [{ "host": "web1", "where": "container:blog-wordpress-1", "name": "php", "version": "8.3.28" }]
            }),
        ),
        case(
            "GHSA-aaaa-bbbb-cccc",
            json!({
                "title": "next.js middleware bypass", "status": "waiting", "statusReason": "user", "updatedAt": "2026-10-21T08:30:00.000Z",
                "handledBy": "responder", "handledAt": "2026-10-21T08:10:00.000Z", "report": "/data/reports/2026-10-21-ghsa.md",
                "assessment": { "rating": "act this week", "why": "api uses next 15.4" },
                "triage": { "path": "propose", "why": "no fix released yet", "rating": "act this week" },
                "pullRequests": ["https://github.com/acme/api/pull/7"], "waitingFor": [{ "kind": "package", "ecosystem": "npm", "name": "next", "atLeast": "15.5.7" }]
            }),
        ),
        case("CVE-2026-0001", json!({ "title": "old openssl", "status": "closed", "statusReason": "fixed", "updatedAt": "2026-10-01T07:00:00.000Z" })),
    ]
    .into_iter()
    .map(|c| (c["key"].as_str().expect("a key").to_string(), c))
    .collect();
    write_state(dir, "cases.json", &cases).expect("writes the cases");
    let at = |s: &str| parse_time(s).expect("a time");
    let notice =
        |event, title: &str| Notice { event, title: title.to_string(), text: "details".to_string(), key: None, severity: None, urls: None, report_path: None };
    keep(dir, &notice(NotifyEvent::Urgent, "act today: acme/blog"), at("2026-10-21T08:05:00.000Z")).expect("keeps");
    keep(dir, &notice(NotifyEvent::Case, &format!("batch {XSS_SCRIPT}")), at("2026-10-21T08:06:00.000Z")).expect("keeps");
    write_state(dir, "retries.json", &json!({ "entries": {} })).expect("writes the queue");
}

fn page_for_seeded_state() -> (TempDir, String) {
    let dir = TempDir::new("cvecondor-dash");
    seed(dir.path());
    let html = render(&config_in(dir.path()));
    (dir, html)
}

/// Every file under `dir`: path → (mode, bytes). The state before and after a command.
fn snapshot(dir: &Path) -> BTreeMap<String, (u32, Vec<u8>)> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, (u32, Vec<u8>)>) {
        for entry in fs::read_dir(dir).expect("reads the dir").filter_map(Result::ok) {
            let path = entry.path();
            let name = path.strip_prefix(base).expect("under base").display().to_string();
            let meta = fs::symlink_metadata(&path).expect("stats");
            if meta.is_dir() {
                out.insert(format!("{name}/"), (meta.permissions().mode(), Vec::new()));
                walk(base, &path, out);
            } else {
                out.insert(name, (meta.permissions().mode(), fs::read(&path).expect("reads the file")));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

#[test]
fn an_empty_state_renders_and_says_there_is_nothing_yet() {
    let dir = TempDir::new("cvecondor-dash-empty");
    let html = render(&config_in(dir.path()));
    assert!(html.starts_with("<!doctype html>"), "{html}");
    assert!(html.contains("Nothing yet"), "{html}");
    for section in ["Health", "Cases", "Inventory", "Secrets", "Inbox", "Reports"] {
        assert!(html.contains(&format!("<h2>{section}</h2>")), "{section}");
    }
    assert!(html.contains("No cases yet.") && html.contains("Not collected yet.") && html.contains("No reports yet."), "{html}");
    // A state dir that does not exist yet is the same page, and is not created by looking.
    let missing = dir.path().join("not-there");
    assert!(render(&config_in(&missing)).contains("Nothing yet"));
    assert!(!missing.exists());
}

#[test]
fn the_page_is_a_static_document_with_no_script_and_no_outside_resources() {
    let (_dir, html) = page_for_seeded_state();
    assert!(html.contains("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'"), "{html}");
    // The seeded attacker text is shown as escaped text; apart from that, no markup that runs or loads anything.
    let markup = html.replace("&lt;script&gt;alert(1)&lt;/script&gt;", "").replace("&quot;&gt;&lt;img src=x onerror=alert(1)&gt;", "");
    for forbidden in ["<script", "<img", "<link", "<iframe", "<form", "<base", " src=", "@import", "url(", "onerror", "onclick", "onmouseover=\""] {
        assert!(!markup.to_lowercase().contains(forbidden), "{forbidden}");
    }
    assert!(html.contains("prefers-color-scheme:dark") && html.contains("name=\"viewport\""));
    // The only hrefs are advisory and pull request links, all http(s) and all rel=noreferrer.
    let hrefs: Vec<&str> = html.split("href=\"").skip(1).collect();
    assert!(!hrefs.is_empty());
    for h in hrefs {
        assert!(h.starts_with("https://") || h.starts_with("http://"), "{h}");
        assert!(h.split('>').next().expect("a tag").ends_with("rel=\"noreferrer\""), "{h}");
    }
    assert!(html.contains("https://github.com/acme/api/pull/7"));
}

#[test]
fn it_shows_health_cases_inventory_secrets_inbox_and_reports_the_way_status_does() {
    let (dir, _) = page_for_seeded_state();
    let reports = dir.path().join("reports");
    fs::create_dir_all(&reports).expect("creates reports/");
    fs::write(reports.join("2026-10-21-ghsa-aaaa.md"), "SECRET-BODY-OF-A-REPORT").expect("writes a report");
    let html = render(&config_in(dir.path()));
    // Health: a failing source and a cycle that is weeks old (the fixture's clock) are what it says first.
    assert!(html.contains("Needs attention:") && html.contains("1 source(s) failing") && html.contains("last cycle "), "{html}");
    assert!(html.contains("nvd (HTTP 503, last ok"), "{html}");
    // Cases: open before waiting before closed, the rating as text.
    let (open, waiting, closed) =
        (html.find("CVE-2026-1111").expect("open"), html.find("GHSA-aaaa-bbbb-cccc").expect("waiting"), html.find("CVE-2026-0001").expect("closed"));
    assert!(open < waiting && waiting < closed);
    assert!(html.contains("<strong>act today</strong>") && html.contains("<strong>act this week</strong>"), "{html}");
    assert!(html.contains("waiting on user: your decision") && html.contains("npm next &gt;= 15.5.7"), "{html}");
    assert!(html.contains("propose: no fix released yet"), "{html}");
    assert!(html.contains("<summary>Closed (1)</summary>"), "{html}");
    assert!(html.contains("php 8.3.28"), "{html}");
    // Inventory and secrets: names, places and fingerprints.
    assert!(html.contains("Items by kind") && html.contains("container:blog-wordpress-1") && html.contains("blog.example.com"), "{html}");
    assert!(html.contains("OPENAI_API_KEY") && html.contains("<code>1a2b3c4d</code>") && html.contains("RAILWAY_TOKEN"), "{html}");
    // Inbox: file names under reports/, nothing marked read. Reports: names only, never bodies.
    assert!(html.contains("2 unread of 2"), "{html}");
    assert!(html.contains("-urgent.md") && html.contains("2026-10-21-ghsa-aaaa.md"), "{html}");
    assert!(!html.contains("SECRET-BODY-OF-A-REPORT"));
}

#[test]
fn what_comes_from_the_state_is_escaped_and_unsafe_links_are_text() {
    let (_dir, html) = page_for_seeded_state();
    assert!(!html.contains(XSS_SCRIPT) && !html.contains(XSS_IMG), "{html}");
    assert!(html.contains("PHP RCE &lt;script&gt;alert(1)&lt;/script&gt;"), "{html}");
    assert!(html.contains("&quot;&gt;&lt;img src=x onerror=alert(1)&gt;"), "{html}");
    // The inbox title, from a notice, is escaped too.
    assert!(html.contains("batch &lt;script&gt;alert(1)&lt;/script&gt;"), "{html}");
    // A link keeps its & as an entity; a javascript: URL is shown, not linked; a quote cannot leave the attribute.
    assert!(html.contains("href=\"https://example.com/advisory?a=1&amp;b=2\" rel=\"noreferrer\""), "{html}");
    assert!(!html.contains("href=\"javascript:") && html.contains("javascript:alert(1)"), "{html}");
    assert!(html.contains("href=\"https://example.com/&quot;onmouseover=&quot;alert(1)\""), "{html}");
}

#[test]
fn a_secret_shows_its_name_and_fingerprint_but_no_value_the_watcher_knows() {
    let dir = TempDir::new("cvecondor-dash-secret");
    seed(dir.path());
    // The state never holds a value, but if text from a feed carried one the config knows, it is scrubbed.
    let mut cases: IndexMap<String, Value> = serde_json::from_str(&fs::read_to_string(dir.path().join("cases.json")).expect("reads")).expect("parses");
    cases["CVE-2026-1111"]["reason"] = json!(format!("leaked {TOKEN} in a log"));
    cases["CVE-2026-1111"]["urls"] = json!([format!("https://example.com/?t={TOKEN}")]);
    write_state(dir.path(), "cases.json", &cases).expect("writes");
    let mut inv: Inventory = serde_json::from_str(&fs::read_to_string(dir.path().join("inventory.json")).expect("reads")).expect("parses");
    inv.secrets[0].risk = format!("value {TOKEN}");
    // A "fingerprint" that is not 8 hex is not shown at all.
    inv.secrets[1].fingerprint = Some(TOKEN.to_string());
    write_state(dir.path(), "inventory.json", &inv).expect("writes");
    // A value that straddles where a title is cut is scrubbed before the cut, so none of it shows.
    cases["CVE-2026-1111"]["title"] = json!(format!("{}{TOKEN}", "x".repeat(190)));
    write_state(dir.path(), "cases.json", &cases).expect("writes");
    let html = render(&config_in(dir.path()));
    assert!(!html.contains(&TOKEN[..8]), "the start of a value cut by the title's limit reached the page");
    assert!(!html.contains(TOKEN), "a value reached the page");
    assert!(!html.contains(&TOKEN[..20]), "part of a value reached the page");
    assert!(html.contains("[redacted]"), "{html}");
    assert!(html.contains("OPENAI_API_KEY") && html.contains("<code>1a2b3c4d</code>"));
}

fn run_dashboard(state: &Path, args: &[&str]) -> std::process::Output {
    let config = state.parent().expect("a parent").join(format!("{}.config.json", state.file_name().expect("a name").to_string_lossy()));
    fs::write(&config, json!({ "stateDir": state, "classifier": false, "collectors": [{ "type": "github", "token": "${DASH_TOKEN}" }] }).to_string())
        .expect("writes the config");
    let out = Command::new(env!("CARGO_BIN_EXE_cvecondor"))
        .arg("dashboard")
        .args(args)
        .arg("--config")
        .arg(&config)
        .env("DASH_TOKEN", TOKEN)
        .output()
        .expect("runs the binary");
    let _ = fs::remove_file(&config);
    out
}

#[test]
fn the_command_prints_the_page_or_writes_it_privately_and_never_touches_the_state() {
    let dir = TempDir::new("cvecondor-dash-cmd");
    let state = dir.path().join("state");
    fs::create_dir_all(&state).expect("creates the state dir");
    seed(&state);
    // A file that does not parse is normally copied to .bad; a read-only command must not.
    fs::write(state.join("known.json"), "{nope").expect("writes");
    fs::write(state.join("inbox-read.json"), "{nope").expect("writes");
    let before = snapshot(&state);

    let out = run_dashboard(&state, &[]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let html = String::from_utf8(out.stdout).expect("utf-8");
    assert!(html.starts_with("<!doctype html>") && html.contains("OPENAI_API_KEY") && !html.contains(TOKEN));

    let file = dir.path().join("dashboard.html");
    let out = run_dashboard(&state, &["--out", &file.display().to_string()]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(fs::metadata(&file).expect("the file").permissions().mode() & 0o777, 0o600);
    assert!(fs::read_to_string(&file).expect("reads").contains("<h2>Cases</h2>"));

    // An older, wider file is replaced by a private one, never written into: whoever holds the old file (here a hard
    // link to it) still sees the old content.
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("chmod");
    let old = dir.path().join("old-link.html");
    fs::hard_link(&file, &old).expect("links");
    fs::write(&file, "old").expect("writes");
    assert!(run_dashboard(&state, &["--out", &file.display().to_string()]).status.success());
    assert_eq!(fs::metadata(&file).expect("the file").permissions().mode() & 0o777, 0o600);
    assert!(fs::read_to_string(&file).expect("reads").contains("<h2>Cases</h2>"));
    assert_eq!(fs::read_to_string(&old).expect("reads"), "old");

    assert_eq!(snapshot(&state), before, "the state dir changed");
    assert!(!state.join("inbox-read.json.bad").exists() && !state.join("known.json.bad").exists());
    // Unread stays unread: the inbox still lists everything for the agent.
    let unread = cvecondor::inbox::unread(&state, false).expect("reads the inbox");
    assert_eq!(unread.len(), 2, "{unread:?}");

    // No state dir at all: still a page, and still no directory made.
    let missing = dir.path().join("missing");
    let out = run_dashboard(&missing, &[]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("Nothing yet"));
    assert!(!missing.exists());
}

#[test]
fn a_watcher_that_cycled_just_now_with_nothing_failing_is_healthy() {
    let dir = TempDir::new("cvecondor-dash-healthy");
    let at = cvecondor::util::iso(cvecondor::util::now());
    write_state(
        dir.path(),
        "last-cycle.json",
        &json!({ "at": at, "polled": 3, "fresh": 0, "firstRead": 0, "osvQueried": [], "newCases": [], "dispatched": [], "reopened": [], "secretsTold": 0, "vendors": 0, "errors": [], "durationMs": 5 }),
    )
    .expect("writes the cycle");
    write_state(dir.path(), "feeds.json", &json!({ "cert-eu": { "okAt": at } })).expect("writes the feeds");
    let html = render(&config_in(dir.path()));
    assert!(html.contains("<strong>Healthy.</strong> Last cycle just now"), "{html}");
    assert!(!html.contains("Needs attention") && !html.contains("Nothing yet"), "{html}");
}

#[test]
fn a_telegram_reply_reader_that_fails_is_not_healthy() {
    let dir = TempDir::new("cvecondor-dash-relay");
    let bot = "123456:dash-bot-token";
    let raw = json!({ "stateDir": dir.path(), "classifier": false, "collectors": [{ "type": "github", "token": "${DASH_TOKEN}" }],
                      "responder": { "agent": "claude" },
                      "notify": [{ "type": "telegram", "botToken": "${DASH_BOT}", "chatId": "42", "replies": true }] });
    let env: Env = [("DASH_TOKEN".to_string(), TOKEN.to_string()), ("DASH_BOT".to_string(), bot.to_string())].into();
    let config = build_config(&raw, &dir.path().join("config.json"), &env).expect("the config builds");
    let at = cvecondor::util::iso(cvecondor::util::now());
    write_state(
        dir.path(),
        "last-cycle.json",
        &json!({ "at": at, "polled": 3, "fresh": 0, "firstRead": 0, "osvQueried": [], "newCases": [], "dispatched": [], "reopened": [], "secretsTold": 0, "vendors": 0, "errors": [], "durationMs": 5 }),
    )
    .expect("writes the cycle");
    write_state(dir.path(), "feeds.json", &json!({ "cert-eu": { "okAt": at } })).expect("writes the feeds");
    // The relay polls apart from the cycle: its failure is only in its own file, never in last-cycle.json.
    let seen = format!("relay-{}-seen.json", &cvecondor::util::sha256_hex(bot.as_bytes())[..8]);
    write_state(dir.path(), &seen, &json!({ "polledAt": at, "error": "HTTP 401" })).expect("writes the relay state");
    let html = render(&config);
    assert!(html.contains("Needs attention:</span> 1 Telegram reply reader(s) failing"), "{html}");
    assert!(!html.contains("<strong>Healthy.</strong>") && !html.contains(bot), "{html}");
}
