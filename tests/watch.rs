// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! The watch cycle against a fixture inventory and a network double: baseline, groups, batches,
//! fix waits, vendor incidents, ratings, secrets.

mod common;

use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use anyhow::Result;
use common::{Net, OsvStub, Recorder, RssItem, SharedNet, TestConfig, inventory, network, recorder, rss, shared, test_config};
use cvecondor::config::{Mode, NotifyEvent};
use cvecondor::feeds::{FeedState, NEWS_SOURCES, ProseItem, SOURCES, SourceDef};
use cvecondor::fixes::{FixWait, WaitPackage};
use cvecondor::matching::Severity;
use cvecondor::state::{read_state, slug, write_state};
use cvecondor::types::Inventory;
use cvecondor::util::{iso, parse_time};
use cvecondor::vendors::UserVendor;
use cvecondor::watch::{Affected, AssessInput, Case, CaseState, CycleDeps, CycleSummary, JudgeVendorFn, RespondFn, Run, assess, case_mode, run_cycle};
use indexmap::IndexMap;
use jiff::Timestamp;
use regex::Regex;
use serde_json::{Value, json};

/// OSV's `database_specific` for a HIGH advisory.
fn high() -> Value {
    json!({ "severity": "HIGH" })
}

fn stub(id: &str, modified: &str) -> OsvStub {
    OsvStub { id: id.to_string(), modified: modified.to_string() }
}

fn matches(pattern: &str, text: &str) -> bool {
    Regex::new(pattern).expect("a valid pattern").is_match(text)
}

/// A case with the required fields, as the state file holds one; `extra` replaces or adds fields.
fn case(key: &str, places: &[(&str, &str)], extra: Value) -> Case {
    let mut raw = json!({
        "key": key, "kind": "vulnerability", "title": "a case", "state": "handled", "reason": "high", "severity": "high", "fixAvailable": false,
        "aliases": [], "urls": [], "sources": [], "targets": [],
        "places": places.iter().map(|(host, place)| json!({ "host": host, "where": place })).collect::<Vec<_>>(),
        "firstSeen": "2026-10-21T07:00:00Z", "updatedAt": "2026-10-21T07:00:00Z"
    });
    if let Value::Object(extra) = extra {
        raw.as_object_mut().expect("an object").extend(extra);
    }
    serde_json::from_value(raw).expect("the case parses")
}

struct Harness {
    config: TestConfig,
    net: SharedNet,
    rec: Recorder,
    responded: Arc<Mutex<Vec<(Case, Mode)>>>,
    runs: Arc<Mutex<Vec<Run>>>,
    clock: AtomicI64,
}

impl Harness {
    fn new(net: Net, extra: Value) -> Self {
        let config = test_config(extra);
        write_state(&config.state_dir, "inventory.json", &inventory()).expect("writes the inventory");
        let clock = parse_time("2026-10-21T08:00:00Z").expect("a time").as_millisecond();
        Self { config, net: shared(net), rec: recorder(), responded: Arc::default(), runs: Arc::default(), clock: AtomicI64::new(clock) }
    }

    fn cycle(&self) -> CycleSummary {
        self.cycle_with(None)
    }

    /// A cycle whose vendor judge answers `label` to every vendor item.
    fn cycle_judging(&self, label: &'static str) -> CycleSummary {
        let judge = move |_: &UserVendor, _: &[ProseItem]| -> Result<String> { Ok(label.to_string()) };
        self.cycle_with(Some(&judge))
    }

    fn cycle_with(&self, judge_vendor: Option<JudgeVendorFn>) -> CycleSummary {
        self.clock.fetch_add(6 * 60_000, Ordering::SeqCst);
        let sources: Vec<SourceDef> = SOURCES.iter().chain(NEWS_SOURCES.iter()).cloned().collect();
        let fetch = network(&self.net, &sources);
        let now = || Timestamp::from_millisecond(self.clock.load(Ordering::SeqCst)).expect("a valid time");
        let respond = |c: &Case, _file: &Path, mode: Mode, run: Run| -> Result<()> {
            self.responded.lock().unwrap_or_else(PoisonError::into_inner).push((c.clone(), mode));
            self.runs.lock().unwrap_or_else(PoisonError::into_inner).push(run);
            Ok(())
        };
        let respond: Option<RespondFn> = if self.config.responder.is_some() { Some(&respond) } else { None };
        let deps = CycleDeps { fetch: &fetch, now: &now, judge: None, judge_vendor, respond, notify: self.rec.notifier(), log: &|_| {} };
        run_cycle(&self.config, &deps).expect("the cycle runs")
    }

    fn net(&self, edit: impl FnOnce(&mut Net)) {
        edit(&mut self.net.lock().unwrap_or_else(PoisonError::into_inner));
    }

    fn cases(&self) -> IndexMap<String, Case> {
        read_state(&self.config.state_dir, "cases.json").unwrap_or_default()
    }

    fn put_case(&self, c: Case) {
        let mut cases = self.cases();
        cases.insert(c.key.clone(), c);
        write_state(&self.config.state_dir, "cases.json", &cases).expect("writes the cases");
    }

    fn advance(&self, ms: i64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }

    fn responded(&self) -> Vec<(Case, Mode)> {
        self.responded.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    fn told(&self, event: NotifyEvent) -> Vec<cvecondor::notify::Notice> {
        self.rec.notices().into_iter().filter(|n| n.event == event).collect()
    }
}

fn claude() -> Value {
    json!({ "responder": { "agent": "claude" } })
}

#[test]
fn one_response_per_advisory_never_twice_and_again_when_the_fix_is_announced() {
    let mut net = Net::new("2026-10-20T00:00:00Z");
    net.feeds.insert("cert-eu".into(), rss(&[]));
    let h = Harness::new(net, claude());
    h.cycle(); // baseline: what the feed already carries is not news
    let advisory = |description: &str| rss(&[RssItem { guid: "adv-2026-018", title: "2026-018: Critical Vulnerabilities in PHP", description }]);
    h.net(|n| {
        n.feeds.insert("cert-eu".into(), advisory("Two critical PHP vulnerabilities could affect all PHP versions. A fix is scheduled."));
    });
    h.cycle();
    assert_eq!(h.responded().len(), 1);
    let (c, _) = &h.responded()[0];
    assert!(c.targets.contains(&"web1 container:blog-wordpress-1 php 8.3.28 exposed: blog.example.com".to_string()));
    assert!(c.reason.contains("mitigate until it ships"));
    h.cycle(); // unchanged feed: nothing new
    assert_eq!(h.responded().len(), 1);
    h.net(|n| {
        n.feeds.insert("cert-eu".into(), advisory("The fixes were released today in PHP 8.3.36. Patch immediately."));
    });
    h.cycle();
    assert_eq!(h.responded().len(), 2);
    assert!(h.responded()[1].0.reopened_at.is_some());
}

#[test]
fn the_baseline_is_told_critical_and_high_already_present_at_install_open_cases_lower_is_recorded_only() {
    let mut net = Net::new("2026-10-20T00:00:00Z");
    net.osv.insert("left-pad".into(), vec![stub("GHSA-high", "2026-01-01T00:00:00Z")]);
    net.osv.insert("right-pad".into(), vec![stub("GHSA-med", "2026-01-01T00:00:00Z")]);
    net.records.insert(
        "GHSA-high".into(),
        json!({
            "id": "GHSA-high", "modified": "2026-01-01T00:00:00Z", "aliases": ["CVE-2026-1111"], "summary": "left-pad RCE", "database_specific": high(),
            "affected": [{ "package": { "ecosystem": "npm", "name": "left-pad" }, "ranges": [{ "type": "SEMVER", "events": [{ "introduced": "0" }, { "fixed": "1.0.1" }] }] }]
        }),
    );
    net.records.insert(
        "GHSA-med".into(),
        json!({ "id": "GHSA-med", "modified": "2026-01-01T00:00:00Z", "summary": "right-pad ReDoS", "database_specific": { "severity": "MODERATE" }, "affected": [] }),
    );
    let h = Harness::new(net, json!({}));
    h.cycle();
    let cases = h.cases();
    assert_eq!(cases["CVE-2026-1111"].state, CaseState::Handled);
    assert_eq!(cases["CVE-2026-1111"].baseline, Some(true));
    assert_eq!(cases.len(), 1, "the moderate baseline finding is recorded in known.json, not opened");
    let told = h.told(NotifyEvent::Case);
    assert_eq!(told.len(), 1, "one message for the batch");
    assert!(matches(r"^1 new case\(s\): 1 (act this week|plan it)", &told[0].title));
    let batch_file = std::fs::read_to_string(told[0].report_path.as_ref().expect("a batch file")).expect("the batch file is written");
    assert!(batch_file.contains("already present at install"));
    assert!(batch_file.contains("left-pad 1.0.0 (package-lock.json) fixed in 1.0.1"));
}

#[test]
fn new_package_advisories_in_one_place_make_one_case_a_medium_one_is_recorded_not_notified() {
    let h = Harness::new(Net::new("2026-10-20T00:00:00Z"), claude());
    h.cycle();
    h.net(|n| {
        n.osv_head = "2026-10-21T09:00:00Z".into();
        n.osv.insert("left-pad".into(), vec![stub("GHSA-aaaa", "2026-10-21T09:00:00Z")]);
        n.osv.insert("right-pad".into(), vec![stub("GHSA-bbbb", "2026-10-21T09:00:00Z")]);
        n.osv.insert("vim".into(), vec![stub("UBUNTU-CVE-2026-1", "2026-10-21T09:00:00Z")]);
        n.records.insert(
            "GHSA-aaaa".into(),
            json!({ "id": "GHSA-aaaa", "modified": "2026-10-21T09:00:00Z", "aliases": ["CVE-2026-1111"], "summary": "left-pad RCE", "database_specific": high(), "affected": [] }),
        );
        n.records.insert(
            "GHSA-bbbb".into(),
            json!({
                "id": "GHSA-bbbb", "modified": "2026-10-21T09:00:00Z", "aliases": ["CVE-2026-2222"], "summary": "right-pad prototype pollution", "database_specific": high(), "affected": []
            }),
        );
        n.records.insert(
            "UBUNTU-CVE-2026-1".into(),
            json!({ "id": "UBUNTU-CVE-2026-1", "modified": "2026-10-21T09:00:00Z", "severity": [{ "type": "Ubuntu", "score": "medium" }], "affected": [] }),
        );
    });
    h.cycle();
    assert_eq!(h.responded().len(), 1);
    assert!(matches(r"^2 vulnerabilities in github repo:acme/api", &h.responded()[0].0.title));
    assert_eq!(h.cases()["UBUNTU-CVE-2026-1"].state, CaseState::Watch);
    assert_eq!(h.told(NotifyEvent::Case).len(), 1, "one message for the batch, none per case");
}

#[test]
fn a_place_group_is_named_after_its_exploited_advisory_not_its_most_severe_one() {
    let kev = json!({
        "vulnerabilities": [{ "cveID": "CVE-2026-2222", "vendorProject": "acme", "product": "right-pad", "vulnerabilityName": "smuggling", "dateAdded": "2026-09-02", "shortDescription": "" }]
    });
    let mut net = Net::new("2026-10-20T00:00:00Z");
    net.feeds.insert("cisa-kev".into(), kev.to_string());
    let h = Harness::new(net, claude());
    h.cycle();
    h.net(|n| {
        n.osv_head = "2026-10-21T09:00:00Z".into();
        n.osv.insert("left-pad".into(), vec![stub("GHSA-aaaa", "2026-10-21T09:00:00Z")]);
        n.osv.insert("right-pad".into(), vec![stub("GHSA-bbbb", "2026-10-21T09:00:00Z")]);
        n.records.insert(
            "GHSA-aaaa".into(),
            json!({
                "id": "GHSA-aaaa", "modified": "2026-10-21T09:00:00Z", "aliases": ["CVE-2026-1111"], "summary": "left-pad TLS name spoofing",
                "database_specific": { "severity": "CRITICAL" }, "affected": []
            }),
        );
        n.records.insert(
            "GHSA-bbbb".into(),
            json!({
                "id": "GHSA-bbbb", "modified": "2026-10-21T09:00:00Z", "aliases": ["CVE-2026-2222"], "summary": "right-pad request smuggling", "database_specific": high(), "affected": []
            }),
        );
    });
    h.cycle();
    let (c, _) = &h.responded()[0];
    assert_eq!(c.key, "CVE-2026-2222");
    assert_eq!(c.exploited, Some(true));
    assert!(matches(r"^2 vulnerabilities in github repo:acme/api: right-pad request smuggling; left-pad", &c.title));
}

#[test]
fn a_batch_is_told_in_one_message_urgent_first_its_results_come_as_one_report_once_every_response_has_finished() {
    let config = test_config(json!({ "responder": { "agent": "claude", "maxPerCycle": 1 } }));
    let dir = config.state_dir.clone();
    write_state(&dir, "inventory.json", &inventory()).expect("writes the inventory");
    let net = shared(Net::new("2026-10-20T00:00:00Z"));
    let rec = recorder();
    let started: Mutex<Vec<Case>> = Mutex::new(Vec::new());
    let clock = AtomicI64::new(parse_time("2026-10-21T08:00:00Z").expect("a time").as_millisecond());
    let finish = |c: &Case, message: &str| {
        let report = c.report.as_ref().expect("a report path");
        std::fs::write(report, format!("## Message\n{message}\n")).expect("writes the report");
        write_state(
            &dir,
            &format!("responses/{}.json", slug(&c.key)),
            &json!({ "key": c.key, "state": "done", "startedAt": "2026-10-21T08:00:00Z", "finishedAt": "2026-10-21T09:00:00Z", "report": report }),
        )
        .expect("writes the response");
    };
    let cycle = || {
        clock.fetch_add(6 * 60_000, Ordering::SeqCst);
        let sources: Vec<SourceDef> = SOURCES.iter().chain(NEWS_SOURCES.iter()).cloned().collect();
        let fetch = network(&net, &sources);
        let now = || Timestamp::from_millisecond(clock.load(Ordering::SeqCst)).expect("a valid time");
        let respond = |c: &Case, _file: &Path, _mode: Mode, _run: Run| -> Result<()> {
            std::fs::create_dir_all(Path::new(c.report.as_ref().expect("a report path")).parent().expect("a parent")).expect("creates the reports dir");
            let at = iso(now());
            write_state(&dir, &format!("responses/{}.json", slug(&c.key)), &json!({ "key": c.key, "state": "running", "startedAt": at }))
                .expect("writes the response");
            started.lock().unwrap_or_else(PoisonError::into_inner).push(c.clone());
            Ok(())
        };
        let deps = CycleDeps { fetch: &fetch, now: &now, judge: None, judge_vendor: None, respond: Some(&respond), notify: rec.notifier(), log: &|_| {} };
        run_cycle(&config, &deps).expect("the cycle runs");
    };
    let started_at = |i: usize| started.lock().unwrap_or_else(PoisonError::into_inner)[i].clone();
    cycle();
    {
        let mut net = net.lock().unwrap_or_else(PoisonError::into_inner);
        net.osv_head = "2026-10-21T09:00:00Z".into();
        net.osv.insert("left-pad".into(), vec![stub("GHSA-aaaa", "2026-10-21T09:00:00Z")]);
        net.osv.insert("certifi".into(), vec![stub("GHSA-cccc", "2026-10-21T09:00:00Z")]);
        net.records.insert(
            "GHSA-aaaa".into(),
            json!({
                "id": "GHSA-aaaa", "modified": "2026-10-21T09:00:00Z", "aliases": ["CVE-2026-1111"], "summary": "left-pad RCE", "database_specific": { "severity": "CRITICAL" }, "affected": []
            }),
        );
        net.records.insert(
            "GHSA-cccc".into(),
            json!({ "id": "GHSA-cccc", "modified": "2026-10-21T09:00:00Z", "aliases": ["CVE-2026-3333"], "summary": "certifi bad root", "database_specific": high(), "affected": [] }),
        );
    }
    cycle();
    let told: Vec<_> = rec.notices().into_iter().filter(|n| n.event == NotifyEvent::Case).collect();
    assert_eq!(told.len(), 1, "both new cases in one message");
    assert!(matches(r"^2 new case\(s\): 1 act this week, 1 plan it$", &told[0].title));
    let text = &told[0].text;
    assert!(text.find("ACT THIS WEEK") < text.find("PLAN IT"), "the urgent one leads");
    assert!(text.contains("• left-pad RCE\n  where: acme/api\n"));
    assert!(text.contains("PLAN IT (1), by place:\n- acme/worker: 1"));
    assert_eq!(started.lock().unwrap_or_else(PoisonError::into_inner).len(), 1, "maxPerCycle still paces the responder");
    assert_eq!(started_at(0).title, "left-pad RCE");
    let reports = || rec.notices().into_iter().filter(|n| n.event == NotifyEvent::Report).collect::<Vec<_>>();
    finish(&started_at(0), "Plan it: the vulnerable path is never called here.\nProposed: bump left-pad to 1.0.1.");
    cycle();
    assert_eq!(reports().len(), 0, "no report while a case in the batch is still pending");
    finish(&started_at(1), "Act this week: certifi is used by the worker for every outbound call.");
    cycle();
    let reports = reports();
    assert_eq!(reports.len(), 1, "one report for the batch");
    assert!(matches(r"^Results for 2 case\(s\): 1 act this week, 1 plan it$", &reports[0].title), "the responder's ratings replace the watcher's");
    assert!(reports[0].text.contains("ACT THIS WEEK (1)\n• certifi bad root (acme/worker)\n  Act this week: certifi is used"));
    assert!(reports[0].text.contains("PLAN IT (1)\n- left-pad RCE (acme/api): Plan it: the vulnerable path is never called here."));
    cycle();
    assert_eq!(rec.notices().len(), 2, "nothing more: no per-case messages, no second report");
}

fn left_pad_wait() -> Value {
    json!([{ "kind": "package", "ecosystem": "npm", "name": "left-pad", "atLeast": "1.0.1" }])
}

fn registry(versions: &[&str]) -> (String, Value) {
    let versions: serde_json::Map<String, Value> = versions.iter().map(|v| ((*v).to_string(), json!({}))).collect();
    ("https://registry.npmjs.org/left-pad".to_string(), json!({ "versions": versions }))
}

#[test]
fn a_wait_already_met_at_its_first_check_a_release_the_response_knew_of_does_not_reopen_the_case() {
    let mut net = Net::new("2026-10-20T00:00:00Z");
    net.routes.push(registry(&["1.0.0", "1.0.1"]));
    let h = Harness::new(net, claude());
    h.cycle();
    h.put_case(case(
        "CVE-2026-9",
        &[("github", "repo:acme/api")],
        json!({ "title": "left-pad RCE", "fixAvailable": true, "waitingFor": left_pad_wait(), "report": "/tmp/r.md" }),
    ));
    h.cycle();
    assert_eq!(h.responded().len(), 0, "no \"fix shipped\" for a release that was already out");
    assert_eq!(h.cases()["CVE-2026-9"].state, CaseState::Handled);
    assert_eq!(h.cases()["CVE-2026-9"].waiting_for, Some(vec![]), "the met wait is dropped");
}

#[test]
fn a_handled_case_waiting_for_a_release_reopens_when_it_ships_to_apply_it_and_remove_the_workaround() {
    let mut net = Net::new("2026-10-20T00:00:00Z");
    net.routes.push(registry(&["1.0.0"]));
    let h = Harness::new(net, claude());
    h.cycle();
    h.put_case(case("CVE-2026-9", &[("github", "repo:acme/api")], json!({ "title": "left-pad RCE", "waitingFor": left_pad_wait(), "report": "/tmp/r.md" })));
    h.cycle();
    assert_eq!(h.responded().len(), 0, "not shipped yet");
    h.net(|n| n.routes = vec![registry(&["1.0.0", "1.0.1"])]);
    h.cycle();
    assert_eq!(h.responded().len(), 0, "checked at most every 30 minutes");
    h.advance(30 * 60_000);
    h.cycle();
    assert_eq!(h.responded().len(), 1);
    let (c, _) = &h.responded()[0];
    assert!(c.reason.contains("fix shipped: npm left-pad >= 1.0.1 (1.0.1); apply it and remove the temporary mitigation"));
    assert_eq!(c.previous_report.as_deref(), Some("/tmp/r.md"));
}

#[test]
fn a_fix_osv_names_only_for_another_distro_release_does_not_reopen_the_case() {
    let record = |fixed_for: &[&str]| -> Value {
        let affected: Vec<Value> = ["Debian:12", "Debian:14"]
            .iter()
            .map(|ecosystem| {
                let mut events = vec![json!({ "introduced": "0" })];
                if fixed_for.contains(ecosystem) {
                    events.push(json!({ "fixed": "1:9.2p1-2+deb12u9" }));
                }
                json!({ "package": { "ecosystem": ecosystem, "name": "openssh" }, "ranges": [{ "type": "ECOSYSTEM", "events": events }] })
            })
            .collect();
        json!({ "id": "DEBIAN-CVE-2026-7", "modified": "2026-10-21T00:00:00Z", "aliases": ["CVE-2026-7"], "affected": affected })
    };
    let mut net = Net::new("2026-10-20T00:00:00Z");
    net.records.insert("DEBIAN-CVE-2026-7".into(), record(&["Debian:14"]));
    let h = Harness::new(net, claude());
    h.cycle();
    let wait = FixWait::Osv { id: "DEBIAN-CVE-2026-7".into(), packages: vec![WaitPackage { ecosystem: "Debian:12".into(), name: "openssh".into() }] };
    h.put_case(case(
        "CVE-2026-7",
        &[("web1", "host")],
        json!({ "title": "openssh", "aliases": ["DEBIAN-CVE-2026-7"], "waitingFor": [serde_json::to_value(&wait).expect("a wait serializes")] }),
    ));
    h.cycle();
    assert_eq!(h.responded().len(), 0, "fixed for Debian 14 only: still waiting on Debian 12");
    h.net(|n| {
        n.records.insert("DEBIAN-CVE-2026-7".into(), record(&["Debian:12", "Debian:14"]));
    });
    h.advance(30 * 60_000);
    h.cycle();
    assert_eq!(h.responded().len(), 1, "fixed for Debian 12 now");
    assert_eq!(h.cases()["CVE-2026-7"].waiting_for, Some(vec![]), "the shipped wait is done");
}

#[test]
fn vendor_news_an_outage_stays_quiet_a_breach_names_the_keys_to_rotate_never_their_values() {
    let mut net = Net::new("2026-10-20T00:00:00Z");
    net.feeds.insert("news:hacker-news".into(), rss(&[]));
    let h = Harness::new(net, json!({}));
    h.cycle();
    h.net(|n| {
        n.feeds.insert(
            "news:hacker-news".into(),
            rss(&[
                RssItem { guid: "hn-1", title: "Railway is down: elevated error rates on deploys", description: "Outage" },
                RssItem {
                    guid: "hn-2",
                    title: "Railway security incident: unauthorized access to customer environment variables",
                    description: "Railway says an attacker accessed secrets; rotate your tokens.",
                },
            ]),
        );
    });
    h.advance(15 * 60_000); // news feeds are polled every 15 minutes
    h.cycle();
    let vendor: Vec<Case> = h.cases().into_values().filter(|c| c.kind == cvecondor::watch::CaseKind::Vendor).collect();
    assert_eq!(vendor.len(), 1);
    let notice = h.told(NotifyEvent::Case).remove(0);
    assert!(matches(r"^1 new case\(s\): 1 act today", &notice.title));
    assert!(notice.text.contains("RAILWAY_TOKEN"));
    assert!(notice.text.contains("STRIPE_SECRET_KEY: set for github repo:acme/api, which deploys on Railway"));
    assert!(!notice.text.contains("OPENAI_API_KEY"), "an unrelated key in another place is not listed");
    let urgent = h.told(NotifyEvent::Urgent);
    assert_eq!(urgent.len(), 1, "act today interrupts the user, once");
    assert!(matches(r"^Act today: Railway: .+ in acme/api: rotate \d+ key\(s\) tied to it$", &urgent[0].title));
    assert_eq!(urgent[0].text, "", "one line, no body");
}

#[test]
fn a_vendor_blog_post_the_classifier_cannot_call_an_incident_opens_no_case_and_pages_nobody() {
    let mut net = Net::new("2026-10-20T00:00:00Z");
    net.feeds.insert("news:hacker-news".into(), rss(&[]));
    let h = Harness::new(net, json!({}));
    h.cycle();
    h.net(|n| {
        n.feeds.insert(
            "news:hacker-news".into(),
            rss(&[RssItem {
                guid: "hn-3",
                title: "Railway: How bug bounty sharpens one researcher's security skills",
                description: "A researcher on the Railway security program tells how hunting each security issue taught them to rotate habits.",
            }]),
        );
    });
    h.advance(15 * 60_000);
    h.cycle_judging("unsure");
    let vendor: Vec<Case> = h.cases().into_values().filter(|c| c.kind == cvecondor::watch::CaseKind::Vendor).collect();
    assert_eq!(vendor.len(), 1, "recorded for the agent");
    assert_eq!(vendor[0].state, CaseState::Unsure, "but not a case to act on");
    assert!(h.told(NotifyEvent::Urgent).is_empty(), "no Act today page");
    assert!(h.told(NotifyEvent::Case).is_empty());
}

#[test]
fn news_of_another_projects_compromise_that_names_a_vendor_only_in_its_summary_opens_no_vendor_case() {
    let mut net = Net::new("2026-10-20T00:00:00Z");
    net.feeds.insert("news:hacker-news".into(), rss(&[]));
    let h = Harness::new(net, json!({}));
    h.cycle();
    h.net(|n| {
        n.feeds.insert(
            "news:hacker-news".into(),
            rss(&[RssItem {
                guid: "hn-4",
                title: "PromptRouter Compromised in Fresh Supply Chain Attack",
                description: "Hackers used compromised Railway CLI OAuth tokens to push and approve malicious packages on PyPI and Docker.",
            }]),
        );
    });
    h.advance(15 * 60_000);
    // The classifier reads "compromised Railway ... tokens" and calls it an incident: the vendor is only the attack's tool, not its subject.
    h.cycle_judging("security-incident");
    assert!(h.cases().values().all(|c| c.kind != cvecondor::watch::CaseKind::Vendor), "no Railway case for PromptRouter's compromise");
    assert!(h.told(NotifyEvent::Urgent).is_empty(), "no Act today page, no keys to rotate");
    assert!(h.told(NotifyEvent::Case).is_empty());
}

#[test]
fn with_a_responder_a_vendor_incident_goes_to_it_and_the_watcher_pages_nobody_itself() {
    let mut net = Net::new("2026-10-20T00:00:00Z");
    net.feeds.insert("news:hacker-news".into(), rss(&[]));
    let h = Harness::new(net, claude());
    h.cycle();
    h.net(|n| {
        n.feeds.insert(
            "news:hacker-news".into(),
            rss(&[RssItem {
                guid: "hn-5",
                title: "Railway security incident: unauthorized access to customer environment variables",
                description: "Railway says an attacker accessed secrets; rotate your tokens.",
            }]),
        );
    });
    h.advance(15 * 60_000);
    h.cycle_judging("security-incident");
    let responded = h.responded();
    assert_eq!(responded.len(), 1, "the responder reads the sources and checks the exposure");
    assert_eq!(responded[0].0.kind, cvecondor::watch::CaseKind::Vendor);
    assert!(h.told(NotifyEvent::Urgent).is_empty(), "a page about keys comes from the responder's triage, not the headline");
    let notice = h.told(NotifyEvent::Case).remove(0);
    assert!(matches(r"^1 new case\(s\): 1 act this week", &notice.title), "{}", notice.title);
}

#[test]
fn acting_is_a_per_place_opt_in() {
    let config = test_config(json!({ "responder": { "agent": "claude", "actOn": ["acme/api", "api.example.com"] } }));
    let inv = inventory();
    let api = ("github", "repo:acme/api");
    let blog = ("web1", "container:blog-wordpress-1");
    assert_eq!(case_mode(&config, &case("a", &[api], json!({})), &inv), Mode::Act);
    assert_eq!(case_mode(&config, &case("a", &[("web1", "container:api")], json!({})), &inv), Mode::Act, "by its public hostname");
    assert_eq!(case_mode(&config, &case("a", &[api, blog], json!({})), &inv), Mode::Propose);
    assert_eq!(case_mode(&test_config(claude()), &case("a", &[api], json!({})), &inv), Mode::Propose);
    let at_install = case("a", &[api], json!({ "baseline": true }));
    assert_eq!(case_mode(&config, &at_install, &inv), Mode::Propose, "found at install: assessed and proposed");
    assert_eq!(case_mode(&config, &Case { exploited: Some(true), ..at_install }, &inv), Mode::Act, "unless exploited in the wild");
    let fixed = case("a", &[blog], json!({ "fixAvailable": true }));
    assert_eq!(case_mode(&config, &fixed, &inv), Mode::Update, "a fixed release is applied by default, opted in or not");
    let except = test_config(json!({ "responder": { "agent": "claude", "updateExcept": ["blog.example.com"] } }));
    assert_eq!(case_mode(&except, &fixed, &inv), Mode::Propose, "unless the service is excepted");
    assert_eq!(case_mode(&config, &Case { fix_available: false, ..fixed }, &inv), Mode::Propose, "no fix: work-arounds need the per-service opt-in");
    let server_packages = case("a", &[("web1", "host")], json!({}));
    let web1 = test_config(json!({ "responder": { "agent": "claude", "actOn": ["web1"] } }));
    assert_eq!(case_mode(&web1, &server_packages, &inv), Mode::Act, "a server's own packages go by its collector name");
}

#[test]
fn the_rating_says_how_serious_it_is_for_this_user_not_the_cvss_label() {
    let inv: Inventory = inventory();
    let item = |host: &str, place: &str, name: &str, version: &str, running: Option<bool>, dev: Option<bool>| Affected {
        host: host.into(),
        r#where: place.into(),
        name: name.into(),
        version: version.into(),
        running,
        dev,
    };
    let rate = |severity: Severity, exploited: bool, affected: &[Affected]| {
        assess(&AssessInput { severity, exploited, malicious: false, affected, inventory: &inv, at_risk: 0 })
    };
    let api = [item("web1", "container:api", "node", "22.23.2", None, None)];
    assert_eq!(rate(Severity::High, true, &api).rating.as_str(), "act today");
    assert!(matches(r"publicly reachable at api\.example\.com", &rate(Severity::High, true, &api).why));
    let stopped = [item("web1", "container:old-shop", "php", "8.2.20", Some(false), None)];
    assert_eq!(rate(Severity::Critical, false, &stopped).rating.as_str(), "not a real risk for you");
    let repo = [item("github", "repo:acme/api", "left-pad", "1.0.0", None, None)];
    assert_eq!(rate(Severity::Critical, false, &repo).rating.as_str(), "act this week");
    let dev = [item("github", "repo:acme/api", "left-pad", "1.0.0", None, Some(true))];
    assert_eq!(rate(Severity::High, false, &dev).rating.as_str(), "not a real risk for you");
}

#[test]
fn secrets_found_where_they_should_not_be_are_told_once_without_values() {
    let h = Harness::new(Net::new("2026-10-20T00:00:00Z"), json!({}));
    let mut inv = inventory();
    inv.secrets.push(
        serde_json::from_value(json!({
            "host": "github", "where": "repo:acme/blog", "location": ".env", "line": 3, "kind": "env-file", "name": "DB_PASSWORD", "fingerprint": "deadbeef",
            "exposure": "committed-env-file", "risk": "public repo: anyone can read it", "providers": ["database"]
        }))
        .expect("a finding"),
    );
    write_state(&h.config.state_dir, "inventory.json", &inv).expect("writes the inventory");
    h.cycle();
    h.cycle();
    let told = h.told(NotifyEvent::Secrets);
    assert_eq!(told.len(), 1);
    assert!(told[0].text.contains("DB_PASSWORD in .env:3 (fp deadbeef)"));
    assert!(
        !told[0].text.contains("OPENAI_API_KEY") && !told[0].text.contains("RAILWAY_TOKEN"),
        "container env and CI secret names are kept for breach impact, not alerted"
    );
}

/// The security-wg index as the feed serves it: two entries (two CVEs) of one release, matching the fixture's Node versions.
fn node_index() -> String {
    let entry = |cve: &str, description: &str| {
        json!({
            "cve": [cve], "vulnerable": "20.x || 22.x", "patched": "^20.19.7 || ^22.23.3", "severity": "high", "description": description,
            "ref": "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases"
        })
    };
    json!({ "1001": entry("CVE-2026-21001", "a permission model bypass"), "1002": entry("CVE-2026-21002", "an HTTP parser flaw") }).to_string()
}

fn node_blog(description: &str) -> String {
    rss(&[RssItem { guid: "node-oct-2026", title: "Wednesday, October 21, 2026 Security Releases", description }])
}

fn sorted(mut list: Vec<String>) -> Vec<String> {
    list.sort();
    list
}

#[test]
fn one_node_security_release_is_one_case_when_the_blog_post_and_the_index_entries_arrive_together() {
    let mut net = Net::new("2026-10-20T00:00:00Z");
    net.feeds.insert("node-security-blog".into(), rss(&[]));
    net.feeds.insert("node-security-index".into(), "{}".into());
    let h = Harness::new(net, claude());
    h.cycle(); // baseline
    h.net(|n| {
        n.feeds.insert("node-security-blog".into(), node_blog("Node.js will release security updates on Wednesday."));
        n.feeds.insert("node-security-index".into(), node_index());
    });
    h.cycle();
    let cases = h.cases();
    assert_eq!(cases.len(), 1, "{:?}", cases.keys().collect::<Vec<_>>());
    let c = cases.values().next().expect("a case");
    assert_eq!(sorted(c.sources.clone()), ["node-security-blog", "node-security-index"]);
    assert_eq!(sorted(c.aliases.clone()), ["CVE-2026-21001", "CVE-2026-21002"]);
    assert_eq!(c.urls.len(), 2);
    assert!(c.fix_available, "the index says the release is out");
    assert_eq!(h.responded().len(), 1, "one response for the release");

    h.cycle(); // nothing new
    assert_eq!(h.cases().len(), 1);
    assert_eq!(h.responded().len(), 1);
}

#[test]
fn index_entries_arriving_after_the_blog_post_join_its_case_and_announce_the_fix() {
    let mut net = Net::new("2026-10-20T00:00:00Z");
    net.feeds.insert("node-security-blog".into(), rss(&[]));
    net.feeds.insert("node-security-index".into(), "{}".into());
    let h = Harness::new(net, claude());
    h.cycle(); // baseline
    h.net(|n| {
        n.feeds.insert("node-security-blog".into(), node_blog("Node.js will release security updates on Wednesday."));
    });
    h.cycle();
    let before = h.cases();
    assert_eq!(before.len(), 1);
    let key = before.keys().next().expect("a case").clone();
    assert!(!before[&key].fix_available, "a post ahead of the release names no fix");
    assert_eq!(h.responded().len(), 1);

    h.net(|n| {
        n.feeds.insert("node-security-index".into(), node_index());
    });
    h.cycle();
    let after = h.cases();
    assert_eq!(after.len(), 1, "{:?}", after.keys().collect::<Vec<_>>());
    let c = &after[&key];
    assert_eq!(sorted(c.sources.clone()), ["node-security-blog", "node-security-index"]);
    assert_eq!(sorted(c.aliases.clone()), ["CVE-2026-21001", "CVE-2026-21002"]);
    assert!(c.fix_available && c.reopened_at.is_some(), "handled: reopened as a fix announced");
    assert!(matches(r"^fix announced: ", &c.reason), "{}", c.reason);
    assert_eq!(h.responded().len(), 2);
}

#[test]
fn a_judging_case_whose_items_are_gone_is_still_judged_not_left_judging_forever() {
    let h = Harness::new(Net::new("2026-10-20T00:00:00Z"), json!({}));
    h.cycle();
    h.put_case(case("PROSE-1", &[], json!({ "state": "judging", "reason": "awaiting the classifier" })));
    h.cycle();
    let c = &h.cases()["PROSE-1"];
    assert_eq!(c.state, CaseState::Unsure, "{}", c.reason);
}

#[test]
fn max_per_cycle_is_a_number_a_half_still_allows_one_response() {
    let h = Harness::new(Net::new("2026-10-20T00:00:00Z"), json!({ "responder": { "agent": "claude", "maxPerCycle": 0.5 } }));
    h.cycle();
    h.net(|n| {
        n.osv_head = "2026-10-21T09:00:00Z".into();
        n.osv.insert("left-pad".into(), vec![stub("GHSA-aaaa", "2026-10-21T09:00:00Z")]);
        n.osv.insert("vim".into(), vec![stub("UBUNTU-CVE-2026-1", "2026-10-21T09:00:00Z")]);
        n.records.insert(
            "GHSA-aaaa".into(),
            json!({ "id": "GHSA-aaaa", "modified": "2026-10-21T09:00:00Z", "aliases": ["CVE-2026-1111"], "summary": "left-pad RCE", "database_specific": high(), "affected": [] }),
        );
        n.records.insert(
            "UBUNTU-CVE-2026-1".into(),
            json!({ "id": "UBUNTU-CVE-2026-1", "modified": "2026-10-21T09:00:00Z", "summary": "vim overflow", "severity": [{ "type": "Ubuntu", "score": "high" }], "affected": [] }),
        );
    });
    h.cycle();
    assert_eq!(h.responded().len(), 1, "{:?}", h.cases().values().map(|c| (&c.key, c.state)).collect::<Vec<_>>());
}

// ---- the retry queue: a response that did not finish is retried, never dropped ----

/// A response record a version before the queue wrote: failed with a bare exit code, the agent's words in its report.
fn failed_response(h: &Harness, key: &str, finished_at: &str, said: &str) {
    let report = h.config.dir.path().join(format!("{}.md", slug(key)));
    std::fs::write(&report, said).expect("writes the report");
    write_state(
        &h.config.state_dir,
        &format!("responses/{}.json", slug(key)),
        &json!({ "key": key, "state": "failed", "startedAt": finished_at, "finishedAt": finished_at, "report": report, "error": "exit 1" }),
    )
    .expect("writes the response");
}

fn handled(key: &str, rating: &str, extra: Value) -> Case {
    let mut c = json!({ "title": key, "assessment": { "rating": rating, "why": "test" }, "handledBy": "responder", "handledAt": "2026-10-20T17:00:00Z" });
    c.as_object_mut().expect("an object").extend(extra.as_object().expect("an object").clone());
    case(key, &[("github", "repo:acme/api")], c)
}

#[test]
fn failed_responses_from_before_the_queue_are_picked_up_and_retried_most_urgent_first_a_few_a_cycle() {
    let h = Harness::new(Net::new("2026-10-20T00:00:00Z"), claude());
    h.cycle();
    let limit = "You've hit your session limit · resets 7:40pm (UTC)\n";
    for (key, rating, extra) in [
        ("CVE-PLAN", "plan it", json!({})),
        ("CVE-WEEK", "act this week", json!({})),
        ("CVE-EXPLOITED", "plan it", json!({ "exploited": true })),
        ("CVE-TODAY", "act today", json!({})),
    ] {
        h.put_case(handled(key, rating, extra));
        failed_response(&h, key, "2026-10-20T17:30:00Z", limit);
    }
    let summary = h.cycle();
    assert_eq!(summary.queued.len(), 4, "every old failed record is queued, once");
    assert_eq!(h.told(NotifyEvent::Report).len(), 1, "one inbox line for the four, not one each");
    let queue = cvecondor::retry::read(&h.config.state_dir);
    assert!(queue.entries.values().all(|e| e.limit && e.reason.contains("resets 7:40pm (UTC)")), "{queue:?}");
    let keys = |runs: Vec<(Case, Mode)>| runs.into_iter().map(|(c, _)| c.key).collect::<Vec<_>>();
    assert_eq!(keys(h.responded()), ["CVE-EXPLOITED", "CVE-TODAY"], "exploited, then act today; maxPerCycle is 2, the reset does not fire all four");
    assert!(h.runs.lock().unwrap_or_else(PoisonError::into_inner).iter().all(|r| !r.batch && r.retry), "a retry reports on its own and says it is one");

    let again = h.cycle();
    assert!(again.queued.is_empty(), "a record already counted is not queued again");
    assert_eq!(keys(h.responded())[2..], ["CVE-WEEK", "CVE-PLAN"], "the next two come next cycle; the two already started wait out their own backoff");
}

#[test]
fn nothing_starts_before_the_agents_reset_and_a_newer_event_for_a_queued_case_replaces_its_retry() {
    let h = Harness::new(Net::new("2026-10-20T00:00:00Z"), claude());
    h.cycle();
    // The agent's limit resets at 19:40 UTC today; it is 08:06.
    h.put_case(handled("CVE-QUEUED", "plan it", json!({})));
    failed_response(&h, "CVE-QUEUED", "2026-10-21T08:00:00Z", "You've hit your session limit · resets 7:40pm (UTC)\n");
    // A fresh case, never run: held too, while the agent is out.
    h.put_case(case("CVE-FRESH", &[("github", "repo:acme/api")], json!({ "state": "pending", "title": "fresh" })));
    h.cycle();
    assert!(h.responded().is_empty(), "paused until the reset: neither the retry nor the new case starts");
    assert_eq!(h.cases()["CVE-FRESH"].state, CaseState::Pending, "the new case waits, it is not lost");

    // The case is reopened by a newer event while queued: one run for it, not that run and a retry.
    let mut reopened = h.cases()["CVE-QUEUED"].clone();
    reopened.state = CaseState::Pending;
    h.put_case(reopened);
    h.advance(12 * 3_600_000);
    h.cycle();
    let started: Vec<(String, bool)> =
        h.responded().into_iter().zip(h.runs.lock().unwrap_or_else(PoisonError::into_inner).iter().map(|r| r.retry)).map(|((c, _), retry)| (c.key, retry)).collect();
    assert_eq!(started.len(), 2, "{started:?}");
    assert!(started.iter().all(|(_, retry)| !retry), "both are new events, run as such: {started:?}");
    assert!(cvecondor::retry::read(&h.config.state_dir).entries.is_empty(), "the newer event took the queued retry's place");
    h.advance(24 * 3_600_000);
    h.cycle();
    assert_eq!(h.responded().len(), 2, "and nothing runs a second time");
}

#[test]
fn a_run_that_finished_after_a_failed_one_clears_the_cases_failure() {
    let h = Harness::new(Net::new("2026-10-20T00:00:00Z"), claude());
    h.cycle();
    let report = h.config.dir.path().join("late.md");
    std::fs::write(&report, "## Message\nfine for now.\n").expect("writes the report");
    // Folded in already (same report and time), with the failure of the run before still on it.
    h.put_case(handled("CVE-LATE", "plan it", json!({ "dispatchError": "exit 1", "report": report, "handledAt": "2026-10-20T17:40:00Z" })));
    write_state(
        &h.config.state_dir,
        "responses/cve-late.json",
        &json!({ "key": "CVE-LATE", "state": "done", "startedAt": "2026-10-20T17:30:00Z", "finishedAt": "2026-10-20T17:40:00Z", "report": report }),
    )
    .expect("writes the response");
    h.cycle();
    assert_eq!(h.cases()["CVE-LATE"].dispatch_error, None);
    assert!(cvecondor::retry::read(&h.config.state_dir).entries.is_empty());
}

#[test]
fn a_failure_with_no_reset_is_retried_after_a_backoff_and_a_cause_that_never_clears_is_told_once() {
    let h = Harness::new(Net::new("2026-10-20T00:00:00Z"), claude());
    h.cycle();
    h.put_case(handled("CVE-BROKEN", "act today", json!({})));
    let fail = |at: &str| {
        write_state(
            &h.config.state_dir,
            "responses/cve-broken.json",
            &json!({ "key": "CVE-BROKEN", "state": "failed", "startedAt": at, "finishedAt": at, "error": "exit 1: Invalid API key · Please run /login" }),
        )
        .expect("writes the response");
    };
    let urgent_lines = || h.told(NotifyEvent::Urgent).into_iter().filter(|n| n.title.starts_with("responder can't run")).count();
    for round in 1..=4 {
        fail(&format!("2026-10-21T08:0{round}:00Z"));
        h.advance(3 * 3_600_000);
        h.cycle();
    }
    let queue = cvecondor::retry::read(&h.config.state_dir);
    assert_eq!(queue.entries["CVE-BROKEN"].attempts, 4);
    assert_eq!(urgent_lines(), 1, "said once at the third time, not on every retry");
    assert!(h.told(NotifyEvent::Urgent).iter().any(|n| n.title.contains("Invalid API key")));
}

const CVE_LIST: &str = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/";

/// `cves/deltaLog.json`: runs newest first, each `(fetchTime, new ids, updated ids)`.
fn cve_log(runs: &[(&str, &[&str], &[&str])]) -> (String, Value) {
    let refs = |ids: &[&str]| ids.iter().map(|id| json!({ "cveId": id })).collect::<Vec<_>>();
    let log: Vec<Value> = runs.iter().map(|(time, new, updated)| json!({ "fetchTime": time, "new": refs(new), "updated": refs(updated) })).collect();
    (format!("{CVE_LIST}deltaLog.json"), Value::Array(log))
}

/// A record at its path in the repository: `cves/2026/109xxx/CVE-2026-109619.json`.
fn cve_record(id: &str, cna: Value, adp: Value) -> (String, Value) {
    let (year, number) = id.strip_prefix("CVE-").and_then(|rest| rest.split_once('-')).expect("a CVE id");
    let url = format!("{CVE_LIST}{year}/{}xxx/{id}.json", &number[..number.len() - 3]);
    (url, json!({ "cveMetadata": { "cveId": id, "state": "PUBLISHED", "dateUpdated": "2026-10-22T09:00:00.000Z" }, "containers": { "cna": cna, "adp": adp } }))
}

/// CISA's ADP container saying the CVE is exploited.
fn adp_exploited() -> Value {
    json!([{ "providerMetadata": { "shortName": "CISA-ADP" }, "metrics": [{ "other": { "type": "ssvc", "content": { "options": [{ "Exploitation": "active" }] } } }] }])
}

/// The PHP RCE of Oct 2026 as the CVE List holds it.
fn php_record() -> Value {
    json!({
        "title": "RCE via stale global state",
        "descriptions": [{ "lang": "en", "value": "PHP has various global state that temporarily points into request memory." }],
        "affected": [{
            "vendor": "PHP Group", "product": "PHP", "packageName": "php-src", "defaultStatus": "unaffected",
            "versions": [
                { "status": "affected", "version": "8.2.*", "lessThan": "8.2.35", "versionType": "semver" },
                { "status": "affected", "version": "8.3.*", "lessThan": "8.3.36", "versionType": "semver" },
                { "status": "affected", "version": "8.4.*", "lessThan": "8.4.27", "versionType": "semver" }
            ]
        }],
        "metrics": [{ "format": "CVSS", "cvssV4_0": { "version": "4.0", "baseSeverity": "CRITICAL", "baseScore": 9.2 } }]
    })
}

#[test]
fn a_cve_list_record_with_semver_ranges_opens_one_case_for_each_php_in_range_with_the_release_that_fixes_it() {
    let mut net = Net::new("2026-10-20T00:00:00Z");
    net.routes = vec![cve_log(&[("2026-10-22T08:00:00.000Z", &[], &["CVE-2026-109619"])]), cve_record("CVE-2026-109619", php_record(), json!([]))];
    let h = Harness::new(net, json!({}));
    h.cycle();
    assert!(h.cases().is_empty(), "the first read of the log is history: the record it lists is not news");
    let feeds: IndexMap<String, FeedState> = read_state(&h.config.state_dir, "feeds.json").unwrap_or_default();
    assert_eq!(feeds["cve-list"].cursor.as_deref(), Some("2026-10-22T08:00:00.000Z"));

    h.net(|n| {
        n.routes = vec![
            cve_log(&[("2026-10-22T09:00:00.000Z", &["CVE-2026-109619"], &[]), ("2026-10-22T08:00:00.000Z", &[], &["CVE-2026-109619"])]),
            cve_record("CVE-2026-109619", php_record(), json!([])),
        ];
    });
    let summary = h.cycle();
    assert_eq!(summary.new_cases, ["CVE-2026-109619"]);
    let c = &h.cases()["CVE-2026-109619"];
    // Told to the user: with no responder the notice is the handling.
    assert_eq!((c.state, c.severity, c.fix_available), (CaseState::Handled, Severity::Critical, true), "{}", c.reason);
    assert_eq!(c.sources, ["cve-list"]);
    assert_eq!(c.title, "CVE-2026-109619: RCE via stale global state");
    assert_eq!(
        sorted(c.targets.clone()),
        sorted(vec![
            "web1 container:blog-wordpress-1 php 8.3.28 exposed: blog.example.com fixed in 8.3.36".to_string(),
            "web1 container:old-shop php 8.2.20 (stopped) fixed in 8.2.35".to_string(),
            "github repo:acme/blog php 8.3 (docker-compose.yml) fixed in 8.3.36".to_string(),
        ])
    );
    assert!(h.cycle().new_cases.is_empty(), "the same log again opens nothing");
}

#[test]
fn a_cve_list_record_with_only_product_and_version_strings_goes_the_name_match_path_never_straight_to_a_case() {
    let strings = |text: &str| json!({ "descriptions": [{ "lang": "en", "value": "A flaw in WordPress." }], "affected": [{ "vendor": "WordPress", "product": "WordPress", "versions": [{ "status": "affected", "version": text }] }] });
    let mut net = Net::new("2026-10-20T00:00:00Z");
    net.routes = vec![cve_log(&[("2026-10-22T08:00:00.000Z", &[], &[])])];
    let h = Harness::new(net, json!({}));
    h.cycle();
    h.net(|n| {
        n.routes = vec![
            cve_log(&[("2026-10-22T09:00:00.000Z", &["CVE-2026-100002", "CVE-2026-100003"], &[]), ("2026-10-22T08:00:00.000Z", &[], &[])]),
            cve_record("CVE-2026-100002", strings("before 6.8.4"), json!([])),
            cve_record("CVE-2026-100003", strings("6.x"), adp_exploited()),
        ];
    });
    h.cycle();
    let cases = h.cases();
    // Without a classifier the name match decides, as for a prose advisory: set aside when unsure, unless the source is high-signal.
    let quiet = &cases["CVE-2026-100002"];
    assert_eq!(quiet.state, CaseState::Unsure, "{}", quiet.reason);
    assert!(quiet.reason.starts_with("name match (no classifier key)"), "{}", quiet.reason);
    assert_eq!(quiet.sources, ["cve-list"]);
    assert!(quiet.targets.iter().any(|t| t.starts_with("github repo:acme/blog wordpress 6.8.3-php8.3-apache")), "{:?}", quiet.targets);
    // CISA's ADP says it is exploited: that makes the record high-signal.
    let loud = &cases["CVE-2026-100003"];
    assert_eq!((loud.state, loud.exploited), (CaseState::Handled, Some(true)), "{}", loud.reason);
}

#[test]
fn a_cve_list_record_of_a_cve_osv_already_reported_joins_its_case_and_makes_it_urgent_when_cisa_says_exploited() {
    let mut net = Net::new("2026-10-20T00:00:00Z");
    net.routes = vec![cve_log(&[("2026-10-22T08:00:00.000Z", &[], &[])])];
    let h = Harness::new(net, json!({}));
    h.cycle();
    h.put_case(case(
        "CVE-2026-5000",
        &[("github", "repo:acme/api")],
        json!({ "state": "watch", "reason": "low: recorded, not notified", "severity": "low", "aliases": ["GHSA-aaaa-bbbb-cccc", "CVE-2026-5000"], "sources": ["osv:npm"], "targets": ["github repo:acme/api left-pad 1.0.0 (package-lock.json)"] }),
    ));
    let left_pad = json!({
        "title": "left-pad prototype pollution",
        "affected": [{ "vendor": "left-pad", "product": "left-pad", "packageName": "left-pad", "collectionURL": "https://www.npmjs.com", "versions": [{ "status": "affected", "version": "0", "lessThan": "1.3.1", "versionType": "semver" }] }]
    });
    h.net(|n| {
        n.routes = vec![
            cve_log(&[("2026-10-22T09:00:00.000Z", &[], &["CVE-2026-5000"]), ("2026-10-22T08:00:00.000Z", &[], &[])]),
            cve_record("CVE-2026-5000", left_pad, adp_exploited()),
        ];
    });
    let summary = h.cycle();
    assert!(summary.new_cases.is_empty(), "{:?}", summary.new_cases);
    let cases = h.cases();
    assert_eq!(cases.len(), 1);
    let c = &cases["CVE-2026-5000"];
    assert_eq!(c.sources, ["osv:npm", "cve-list"]);
    assert!(c.urls.contains(&"https://www.cve.org/CVERecord?id=CVE-2026-5000".to_string()));
    assert_eq!((c.state, c.exploited, c.fix_available), (CaseState::Handled, Some(true), true), "{}", c.reason);
    assert!(c.targets.iter().any(|t| t.ends_with("fixed in 1.3.1")), "{:?}", c.targets);
}
