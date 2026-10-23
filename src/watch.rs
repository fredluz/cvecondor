// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! One watch cycle: poll feeds, match against the inventory, keep one case per
//! vulnerability or vendor incident, track what each open case waits for, and
//! hand each case worth a response to the responder (or straight to the user).
//! Critical and high are notified, the existing baseline included; lower is
//! recorded only. Nothing here runs a model except the optional classifier.

use std::collections::HashSet;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, PoisonError};
use std::time::Instant;

use anyhow::{Result, bail};
use indexmap::{IndexMap, IndexSet};
use jiff::Timestamp;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::config::{Config, Mode, NotifyEvent, redact};
use crate::cvelist;
use crate::feeds::{FeedState, NEWS_SOURCES, NodeIndexEntry, PollOptions, PollResult, ProseItem, SOURCES, SourceDef, poll_sources};
use crate::fixes::{FixWait, WaitPackage, check_wait, describe_wait};
use crate::http::Fetch;
use crate::matching::{
    OsvAffected, OsvHit, OsvRecord, ProseCandidate, Severity, Target, Verdict, at_least, classify, describe_secret, describe_target, judge, node_index_matches,
    osv_family, osv_fixes, osv_query, osv_record, osv_severity, place_name, prose_candidates, secrets_at_risk, target_for,
};
use crate::notify::{Notice, Notifier};
use crate::responder::message_of;
use crate::retry::{self, Queue};
use crate::secrets::{Exposure, SecretFinding, finding_key};
use crate::state::{glob_match, read_state, slug, write_file_atomic, write_state};
use crate::types::{Inventory, InventoryItem};
use crate::util::{iso, local_date, parallel_map, parse_time};
use crate::vendors::{
    RotationMap, UserVendor, VENDOR_LABELS, detect_vendors, rotation_for, vendor_candidates, vendor_input, vendor_instructions, vendor_sources,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaseState {
    Watch,
    NotAffected,
    Unsure,
    Judging,
    Pending,
    Handled,
}

impl CaseState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Watch => "watch",
            Self::NotAffected => "not-affected",
            Self::Unsure => "unsure",
            Self::Judging => "judging",
            Self::Pending => "pending",
            Self::Handled => "handled",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Place {
    pub host: String,
    pub r#where: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaseKind {
    Vulnerability,
    Vendor,
}

/// Who closed a case. `agent`: the agent in charge handled it in conversation and recorded it (`record`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HandledBy {
    Responder,
    Notice,
    Agent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Case {
    pub key: String,
    pub kind: CaseKind,
    pub title: String,
    pub state: CaseState,
    pub reason: String,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exploited: Option<bool>,
    pub fix_available: bool,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub sources: Vec<String>,
    /// One line per affected inventory item.
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub places: Vec<Place>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<bool>,
    /// Prose items kept for re-judging and for the responder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<ProseItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub osv_ids: Option<IndexMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judge_failures: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub high_signal: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Keys and env vars to rotate (names, places, fingerprints; never values).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at_risk: Option<Vec<String>>,
    /// What the case waits for; checked every cycle while it is handled and unfixed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting_for: Option<Vec<FixWait>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_checked_at: Option<String>,
    /// The waits (as JSON) checked at least once: one already met at its first check was out when it was recorded, so nothing new shipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waits_checked: Option<Vec<String>>,
    /// The batch (cycle time) this case was told in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch: Option<String>,
    pub first_seen: String,
    pub updated_at: String,
    /// Found by the first look at a place (the install baseline), not by a new advisory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<bool>,
    /// The affected inventory items (capped), for the assessment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affected: Option<Vec<Affected>>,
    /// How serious it is for this user, recomputed at dispatch; the responder confirms or revises it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assessment: Option<Assessment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handled_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handled_by: Option<HandledBy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<String>,
    /// The previous response's report, for a reopened case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_report: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reopened_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatch_error: Option<String>,
    /// The responder's triage: the path it followed and the fact that decided it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triage: Option<Triage>,
}

/// `known.json`: what the watcher has already seen.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Known {
    /// OSV family → vuln id → modified, for every match ever seen (the baseline included).
    #[serde(default)]
    pub osv: IndexMap<String, IndexMap<String, String>>,
    #[serde(default)]
    pub osv_queried_at: IndexMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_index: Option<Vec<String>>,
    /// Secret findings already told to the user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResponseState {
    Running,
    Done,
    Failed,
}

/// A finished (or running) response, written by the responder runner; merged into its case at the next cycle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseRecord {
    pub key: String,
    pub state: ResponseState,
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waits: Option<Vec<FixWait>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triage: Option<Triage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// The urgent lines this case's runs sent, so a retry does not send them again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urgent: Vec<String>,
}

/// Judges one prose candidate (the classifier, or a stand-in).
pub type JudgeFn<'a> = &'a (dyn Fn(&ProseCandidate) -> anyhow::Result<Verdict> + Sync);
/// Judges a vendor incident: the label (`security-incident`, `not-security`, `unsure`).
pub type JudgeVendorFn<'a> = &'a (dyn Fn(&UserVendor, &[ProseItem]) -> anyhow::Result<String> + Sync);
/// How a response is started: in its cycle's batch (a new case) or on its own, and whether it is another run of a
/// case whose last run did not finish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Run {
    pub batch: bool,
    pub retry: bool,
}

/// Starts a response for a case: the case, its case file, the mode, how.
pub type RespondFn<'a> = &'a (dyn Fn(&Case, &Path, Mode, Run) -> anyhow::Result<()> + Sync);

/// What a cycle needs from outside, so tests and replays can swap each piece.
pub struct CycleDeps<'a> {
    pub fetch: &'a dyn Fetch,
    pub now: &'a (dyn Fn() -> Timestamp + Sync),
    /// Replaces the classifier (tests, replays).
    pub judge: Option<JudgeFn<'a>>,
    pub judge_vendor: Option<JudgeVendorFn<'a>>,
    /// Starts a response; returns once it has started (not finished). Absent: cases are notified directly.
    pub respond: Option<RespondFn<'a>>,
    pub notify: Notifier,
    pub log: &'a (dyn Fn(&str) + Sync),
}

/// `last-cycle.json`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CycleSummary {
    pub at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
    pub polled: usize,
    pub fresh: usize,
    /// Sources read for the first time this cycle: their current items are history, not news.
    pub first_read: usize,
    pub osv_queried: Vec<String>,
    pub new_cases: Vec<String>,
    pub dispatched: Vec<String>,
    /// Queued cases started again this cycle.
    #[serde(default)]
    pub retried: Vec<String>,
    /// Cases whose response did not finish and entered the retry queue this cycle.
    #[serde(default)]
    pub queued: Vec<String>,
    pub reopened: Vec<String>,
    pub secrets_told: usize,
    pub vendors: usize,
    pub errors: Vec<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Rating {
    #[serde(rename = "act today")]
    ActToday,
    #[serde(rename = "act this week")]
    ActThisWeek,
    #[serde(rename = "plan it")]
    PlanIt,
    #[serde(rename = "not a real risk for you")]
    NotARealRisk,
}

impl Rating {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ActToday => "act today",
            Self::ActThisWeek => "act this week",
            Self::PlanIt => "plan it",
            Self::NotARealRisk => "not a real risk for you",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Assessment {
    pub rating: Rating,
    pub why: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Affected {
    pub host: String,
    pub r#where: String,
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub running: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<bool>,
}

/// The responder's paths (`agent/respond/<path>.md`); `not-affected` and `already-handled` end at triage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TriagePath {
    Update,
    NotExploitable,
    Workaround,
    Shutdown,
    Propose,
    Breach,
    Distrust,
    NotAffected,
    AlreadyHandled,
}

/// The responder's triage: the path it followed and the fact that decided it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Triage {
    pub path: TriagePath,
    pub why: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rating: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix_released: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exploitable: Option<String>,
}

/// Urgency order: what the user must act on first leads every batch message.
const RANK: [Rating; 4] = [Rating::ActToday, Rating::ActThisWeek, Rating::PlanIt, Rating::NotARealRisk];

/// `reports/<local date>-<slug of the key>.md`.
pub fn report_path(config: &Config, key: &str, now: Timestamp) -> PathBuf {
    config.state_dir.join("reports").join(format!("{}-{}.md", crate::util::local_date(now, &config.timezone), crate::state::slug(key)))
}

fn merge_waits(a: Option<&[FixWait]>, b: &[FixWait]) -> Vec<FixWait> {
    let mut out: IndexMap<String, FixWait> = IndexMap::new();
    for w in a.unwrap_or_default().iter().chain(b) {
        out.insert(serde_json::to_string(w).unwrap_or_default(), w.clone());
    }
    out.into_values().collect()
}

/// Folds finished responses (their report and what the case now waits for) into the cases.
pub fn merge_responses(dir: &Path, cases: &mut IndexMap<String, Case>, at: &str) -> usize {
    let mut merged = 0;
    for record in read_responses(dir) {
        let Some(c) = cases.get_mut(&record.key) else { continue };
        if record.state == ResponseState::Running {
            continue;
        }
        // What the latest run says is the case's last error, also when it was already folded in: a run that finished
        // after one that failed clears the failure.
        c.dispatch_error = record.error.clone();
        if c.report == record.report && c.handled_at == record.finished_at {
            continue;
        }
        c.report = record.report.clone();
        c.handled_at = Some(record.finished_at.clone().unwrap_or_else(|| at.to_string()));
        if let Some(waits) = record.waits.as_deref().filter(|w| !w.is_empty()) {
            c.waiting_for = Some(merge_waits(c.waiting_for.as_deref(), waits));
        }
        if record.triage.is_some() {
            c.triage = record.triage.clone();
        }
        merged += 1;
    }
    merged
}

/// Every `responses/*.json` that parses.
pub fn read_responses(dir: &Path) -> Vec<ResponseRecord> {
    let Ok(entries) = std::fs::read_dir(dir.join("responses")) else { return Vec::new() };
    let mut files: Vec<String> = entries.filter_map(|e| e.ok()?.file_name().into_string().ok()).filter(|f| f.ends_with(".json")).collect();
    files.sort();
    files.iter().filter_map(|f| crate::state::read_state::<ResponseRecord>(dir, &format!("responses/{f}"))).collect()
}

/// The responder's rating when its message leads with one ("Plan it (not act this week): …"), else the watcher's.
pub fn final_rating(c: &Case, message: &str) -> Rating {
    static LEAD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^[^A-Za-z0-9_]*(act today|act this week|plan it|not a real risk)").expect("valid regex"));
    let lead = LEAD.captures(message).map(|m| m[1].to_lowercase());
    lead.and_then(|lead| RANK.into_iter().find(|r| r.as_str().starts_with(&lead))).or_else(|| c.assessment.as_ref().map(|a| a.rating)).unwrap_or(Rating::PlanIt)
}

/// The cases that turned pending in one cycle: told in one message, their results reported together once all are done.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Batch {
    pub id: String,
    pub keys: Vec<String>,
    /// The batch file: every case in full.
    pub report: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub told_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_at: Option<String>,
}

/// Critical and high are told in full on top of a batch message; the other ratings are counted per place.
const HIGHLIGHT: [Rating; 2] = [Rating::ActToday, Rating::ActThisWeek];

/// Words that say a fix is out. ASCII `\b` and case folding, as in JS (`(?-u)`).
static FIX_WORDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i-u)\b(fixed in|fix(es)? (is|are|was|were) (now )?(available|released)|patched in|security release[sd]? (is|are) (now )?available|upgrade to|update to|released (the )?fix|released,? with fix(es)? for)",
    )
    .expect("valid regex")
});

/// Node's blog posts the same "<date> Security Releases" title a week ahead and again on release day.
static NODE_RELEASE_DAY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i-u)(\w+ \d{1,2}, \d{4}) Security Releases").expect("valid regex"));
static CRITICAL_WORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i-u)\bcritical\b").expect("valid regex"));
static HIGH_WORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i-u)\bhigh\b").expect("valid regex"));

/// `Month D, YYYY 00:00 UTC` (what the JS `Date.parse` makes of it): the month by its first three letters. Like V8, a day
/// past the end of the month rolls over (`February 31, 2026` is 3 March).
fn parse_day_utc(day: &str) -> Option<Timestamp> {
    const MONTHS: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    let mut parts = day.split(' ');
    let prefix = parts.next()?.chars().take(3).collect::<String>().to_lowercase();
    let month = MONTHS.iter().position(|m| *m == prefix)? + 1;
    let d: i64 = parts.next()?.trim_end_matches(',').parse().ok()?;
    if !(1..=31).contains(&d) {
        return None;
    }
    let year: i16 = parts.next()?.parse().ok()?;
    let date = jiff::civil::Date::new(year, i8::try_from(month).ok()?, 1).ok()?.checked_add(jiff::Span::new().days(d - 1)).ok()?;
    date.at(0, 0, 0, 0).to_zoned(jiff::tz::TimeZone::UTC).ok().map(|z| z.timestamp())
}

/// On or after the date in a Node "Security Releases" title, the fixes are out.
fn node_released(i: &ProseItem) -> bool {
    if i.source != "node-security-blog" {
        return false;
    }
    let Some(day) = NODE_RELEASE_DAY.captures(&i.title).map(|m| m[1].to_string()) else { return false };
    let Some(published) = i.published.as_deref().filter(|p| !p.is_empty()).and_then(parse_time) else { return false };
    parse_day_utc(&day).is_some_and(|released| published >= released)
}

fn fix_named(i: &ProseItem) -> bool {
    FIX_WORDS.is_match(&format!("{} {}", i.title, i.text)) || node_released(i)
}

/// `cases/<slug of the key>.json`: the case file a responder works from.
pub fn case_path(state_dir: &Path, key: &str) -> PathBuf {
    state_dir.join("cases").join(format!("{}.json", slug(key)))
}

fn place_key(p: &Place) -> String {
    format!("{} {}", p.host, p.r#where)
}

fn lossy(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// A string set in JS terms: present and not empty.
fn is_set(s: &Option<String>) -> bool {
    s.as_deref().is_some_and(|s| !s.is_empty())
}

fn unique<I: IntoIterator<Item = String>>(items: I) -> Vec<String> {
    items.into_iter().collect::<IndexSet<String>>().into_iter().collect()
}

/// Length in UTF-16 code units, what JS `.length` counts.
fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// JS `s.slice(0, n)` on whole characters: the longest prefix of at most `n` UTF-16 code units.
fn take_utf16(s: &str, n: usize) -> &str {
    let mut used = 0;
    for (i, c) in s.char_indices() {
        used += c.len_utf16();
        if used > n {
            return &s[..i];
        }
    }
    s
}

pub(crate) fn clip(s: &str, n: usize) -> String {
    if utf16_len(s) <= n { s.to_string() } else { format!("{}…", take_utf16(s, n - 1)) }
}

/// Index in `ORDER` (`critical` first).
fn severity_order(s: Severity) -> usize {
    match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Unknown => 4,
    }
}

fn rating_order(r: Rating) -> usize {
    RANK.iter().position(|x| *x == r).unwrap_or(RANK.len())
}

fn rating_of(c: &Case) -> Rating {
    c.assessment.as_ref().map_or(Rating::PlanIt, |a| a.rating)
}

/// Who is retried first: what is exploited, then by rating, severity and priority.
fn retry_order(a: &Case, b: &Case) -> std::cmp::Ordering {
    (b.exploited == Some(true))
        .cmp(&(a.exploited == Some(true)))
        .then(rating_order(rating_of(a)).cmp(&rating_order(rating_of(b))))
        .then(severity_order(a.severity).cmp(&severity_order(b.severity)))
        .then((b.priority == Some(true)).cmp(&(a.priority == Some(true))))
}

/// The decision the first look at a vulnerability makes: told or recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub state: CaseState,
    pub reason: String,
}

/// Critical and high are told; lower is recorded. Malicious packages and exploited vulnerabilities always are.
pub fn package_decision(severity: Severity, fix_available: bool, exploited: bool, targets: &[Target], malicious: bool) -> Decision {
    if malicious {
        return Decision { state: CaseState::Pending, reason: "malicious package".into() };
    }
    if exploited {
        return Decision { state: CaseState::Pending, reason: "exploited in the wild (CISA KEV)".into() };
    }
    if !at_least(severity, Severity::High) {
        return Decision { state: CaseState::Watch, reason: format!("{}: recorded, not notified", severity.as_str()) };
    }
    let notes: Vec<&str> = [
        if targets.iter().all(|t| t.item.running == Some(false)) { "only stopped containers carry it" } else { "" },
        if targets.iter().all(|t| t.item.dev == Some(true)) { "development dependency only" } else { "" },
        if fix_available { "" } else { "no fixed version yet: mitigate until it ships" },
    ]
    .into_iter()
    .filter(|n| !n.is_empty())
    .collect();
    let reason = if notes.is_empty() { severity.as_str().to_string() } else { format!("{} ({})", severity.as_str(), notes.join("; ")) };
    Decision { state: CaseState::Pending, reason }
}

/// `act` only when every place the case touches is opted in (`responder.actOn`); otherwise `update` when a
/// fixed release exists, `responder.updateWhenFixed` is on (the default) and no place is in `updateExcept`;
/// otherwise `propose`. What was already there at install is assessed and proposed, not acted on, unless it
/// is exploited in the wild.
pub fn case_mode(config: &Config, c: &Case, inventory: &Inventory) -> Mode {
    let responder = config.responder.as_ref();
    if c.places.is_empty() || (c.baseline == Some(true) && c.exploited != Some(true)) {
        return Mode::Propose;
    }
    let listed = |patterns: &[String], p: &Place| -> bool {
        let names = std::iter::once(place_name(&p.host, &p.r#where))
            .chain(inventory.services.iter().filter(|s| s.host == p.host && s.r#where == p.r#where).flat_map(|s| s.exposed.iter().cloned()));
        names.into_iter().any(|name| patterns.iter().any(|pattern| glob_match(pattern, &name)))
    };
    if let Some(r) = responder
        && !r.act_on.is_empty()
        && c.places.iter().all(|p| listed(&r.act_on, p))
    {
        return Mode::Act;
    }
    match responder {
        Some(r) if c.fix_available && r.update_when_fixed && !c.places.iter().any(|p| listed(&r.update_except, p)) => Mode::Update,
        _ => Mode::Propose,
    }
}

/// What `assess` reads.
#[derive(Debug, Clone)]
pub struct AssessInput<'a> {
    pub severity: Severity,
    pub exploited: bool,
    pub malicious: bool,
    pub affected: &'a [Affected],
    pub inventory: &'a Inventory,
    /// How many secrets are stored at the affected places.
    pub at_risk: usize,
}

/// How serious it is for this user, from what the watcher knows: exploited in the wild, a running service,
/// public exposure, what is at stake. Whether the vulnerable code path is reachable is the responder's
/// finding; until it reports, the rating says so.
pub fn assess(input: &AssessInput) -> Assessment {
    let affected = input.affected;
    let exposed: Vec<String> = unique(
        input.inventory.services.iter().filter(|s| affected.iter().any(|a| a.host == s.host && a.r#where == s.r#where)).flat_map(|s| s.exposed.iter().cloned()),
    );
    let running_count = affected.iter().filter(|a| !a.r#where.starts_with("repo:") && a.running != Some(false)).count();
    let stake = if input.at_risk > 0 { format!("; {} secret(s) stored there", input.at_risk) } else { String::new() };
    let unknown_path = "; whether the vulnerable code path is used is not confirmed yet";
    let reachable = exposed.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
    let rated = |rating: Rating, why: String| Assessment { rating, why };
    if input.malicious {
        return rated(Rating::ActToday, format!("malicious package: assume whatever installed or ran it is compromised{stake}"));
    }
    if !affected.is_empty() && affected.iter().all(|a| a.running == Some(false)) {
        return rated(Rating::NotARealRisk, "only stopped containers carry it; it matters again if they are started".into());
    }
    if !affected.is_empty() && affected.iter().all(|a| a.dev == Some(true)) {
        let rating = if input.severity == Severity::Critical { Rating::PlanIt } else { Rating::NotARealRisk };
        return rated(rating, "only a development dependency: it never runs in production".into());
    }
    if input.exploited {
        return if running_count > 0 || !exposed.is_empty() {
            let reach = if exposed.is_empty() { String::new() } else { format!(", publicly reachable at {reachable}") };
            rated(Rating::ActToday, format!("exploited in the wild and running here{reach}{stake}"))
        } else {
            rated(Rating::ActThisWeek, format!("exploited in the wild; it is in your code, where it runs is not known to the watcher{stake}"))
        };
    }
    if input.severity == Severity::Critical && !exposed.is_empty() {
        return rated(Rating::ActToday, format!("critical and publicly reachable at {reachable}{stake}{unknown_path}"));
    }
    if input.severity == Severity::Critical || (input.severity == Severity::High && !exposed.is_empty()) {
        let place = if !exposed.is_empty() {
            format!(", publicly reachable at {reachable}")
        } else if running_count > 0 {
            ", in a running service".to_string()
        } else {
            ", in your code".to_string()
        };
        return rated(Rating::ActThisWeek, format!("{}{place}{stake}{unknown_path}", input.severity.as_str()));
    }
    if input.severity == Severity::High || input.severity == Severity::Unknown {
        let label = if input.severity == Severity::Unknown { "severity not rated" } else { "high" };
        return rated(Rating::PlanIt, format!("{label}, not shown as publicly reachable{stake}{unknown_path}"));
    }
    rated(Rating::NotARealRisk, format!("{}: recorded only", input.severity.as_str()))
}

fn affected_of(targets: &[Target]) -> Vec<Affected> {
    targets
        .iter()
        .take(80)
        .map(|t| Affected {
            host: t.item.host.clone(),
            r#where: t.item.r#where.clone(),
            name: t.item.name.clone(),
            version: t.item.version.clone(),
            running: (t.item.running == Some(false)).then_some(false),
            dev: (t.item.dev == Some(true)).then_some(true),
        })
        .collect()
}

fn places_of(targets: &[Target]) -> Vec<Place> {
    let mut out: IndexMap<String, Place> = IndexMap::new();
    for t in targets {
        out.insert(format!("{} {}", t.item.host, t.item.r#where), Place { host: t.item.host.clone(), r#where: t.item.r#where.clone() });
    }
    out.into_values().collect()
}

fn merge_places(a: &[Place], b: &[Place]) -> Vec<Place> {
    let mut out: IndexMap<String, Place> = IndexMap::new();
    for p in a.iter().chain(b) {
        out.insert(place_key(p), p.clone());
    }
    out.into_values().collect()
}

/// A case with its required fields; the caller sets the rest.
fn new_case(key: String, kind: CaseKind, title: String, state: CaseState, reason: String, severity: Severity, at: &str) -> Case {
    Case {
        key,
        kind,
        title,
        state,
        reason,
        severity,
        exploited: None,
        fix_available: false,
        aliases: Vec::new(),
        urls: Vec::new(),
        sources: Vec::new(),
        targets: Vec::new(),
        places: Vec::new(),
        priority: None,
        items: None,
        terms: None,
        osv_ids: None,
        judge_failures: None,
        high_signal: None,
        vendor: None,
        at_risk: None,
        waiting_for: None,
        wait_checked_at: None,
        waits_checked: None,
        batch: None,
        first_seen: at.to_string(),
        updated_at: at.to_string(),
        baseline: None,
        affected: None,
        assessment: None,
        handled_at: None,
        handled_by: None,
        report: None,
        previous_report: None,
        reopened_at: None,
        dispatch_error: None,
        triage: None,
    }
}

/// The first case, in order, that has this key or one of these ids among its aliases.
fn by_alias(cases: &IndexMap<String, Case>, ids: &[String]) -> Option<String> {
    cases.values().find(|c| ids.iter().any(|id| c.key == *id || c.aliases.contains(id))).map(|c| c.key.clone())
}

/// Puts the case back in front of the user: a fix shipped or was announced.
fn reopen(c: &mut Case, summary: &mut CycleSummary, at: &str, reason: String) {
    c.state = CaseState::Pending;
    c.fix_available = true;
    c.reopened_at = Some(at.to_string());
    c.reason = reason;
    c.previous_report = c.report.clone().or_else(|| c.previous_report.take());
    c.updated_at = at.to_string();
    summary.reopened.push(c.key.clone());
}

/// Adds a cycle error (redacted, cut to 300 characters).
fn record_error(config: &Config, summary: &mut CycleSummary, place: &str, e: &dyn Display) {
    summary.errors.push(take_utf16(&redact(config, &format!("{place}: {e}")), 300).to_string());
}

/// Delivers a notice; an error when it reached no one and something failed.
fn send(notify: &Notifier, notice: &Notice) -> Result<()> {
    let result = notify(notice);
    if result.sent.is_empty() && !result.errors.is_empty() {
        bail!("{}", result.errors.join("; "));
    }
    Ok(())
}

/// The OSV vulnerability an OSV hit names, kept as the cache holds it: what matching reads, nothing else.
fn record_for(records: &Mutex<IndexMap<String, OsvRecord>>, id: &str, modified: &str, fetch: &dyn Fetch) -> Result<OsvRecord> {
    if let Some(cached) = records.lock().unwrap_or_else(PoisonError::into_inner).get(id).filter(|r| r.modified == modified) {
        return Ok(cached.clone());
    }
    let record = osv_record(id, fetch)?;
    let kept = OsvRecord {
        id: record.id,
        modified: record.modified,
        aliases: record.aliases,
        summary: record.summary,
        details: None,
        severity: record.severity,
        database_specific: record.database_specific,
        affected: record
            .affected
            .map(|list| list.into_iter().map(|a| OsvAffected { package: a.package, ranges: a.ranges, versions: None, ecosystem_specific: None }).collect()),
    };
    records.lock().unwrap_or_else(PoisonError::into_inner).insert(id.to_string(), kept.clone());
    Ok(kept)
}

/// One OSV hit to open or update a case for.
struct Work {
    hit: OsvHit,
    family: String,
    baseline: bool,
}

/// What one cycle reads and changes, so each phase is a method.
struct Cycle<'a, 'b> {
    config: &'a Config,
    deps: &'a CycleDeps<'b>,
    inventory: &'a Inventory,
    now: Timestamp,
    at: String,
    summary: CycleSummary,
    cases: IndexMap<String, Case>,
    known: Known,
    queue: Queue,
}

/// One watch cycle. `run_cycle` does not lock: callers hold `state::with_lock(dir, "cycle", …)`.
pub fn run_cycle(config: &Config, deps: &CycleDeps) -> Result<CycleSummary> {
    let started = Instant::now();
    let now = (deps.now)();
    let at = iso(now);
    let dir = config.state_dir.as_path();
    let mut summary = CycleSummary { at: at.clone(), ..CycleSummary::default() };
    let Some(inventory) = read_state::<Inventory>(dir, "inventory.json") else {
        summary.skipped = Some("no inventory yet".to_string());
        return Ok(summary);
    };
    let mut cy = Cycle {
        config,
        deps,
        inventory: &inventory,
        now,
        at,
        summary,
        cases: read_state(dir, "cases.json").unwrap_or_default(),
        known: read_state(dir, "known.json").unwrap_or_default(),
        queue: retry::read(dir),
    };
    let records: Mutex<IndexMap<String, OsvRecord>> = Mutex::new(read_state(dir, "osv-records.json").unwrap_or_default());
    let mut rotation = RotationMap::new();
    if let Some(path) = &config.rotation_map {
        match std::fs::read_to_string(path).map_err(anyhow::Error::from).and_then(|text| Ok(serde_json::from_str::<RotationMap>(&text)?)) {
            Ok(map) => rotation = map,
            Err(e) => record_error(config, &mut cy.summary, "rotationMap", &e),
        }
    }

    merge_responses(dir, &mut cy.cases, &cy.at);
    let absorbed = retry::absorb(&mut cy.queue, &read_responses(dir), &cy.cases, now);
    if !absorbed.queued.is_empty() {
        if let Err(e) = send(&deps.notify, &retry::queued_notice(&cy.queue, &cy.cases, &absorbed.queued)) {
            record_error(config, &mut cy.summary, "retry notice", &e);
        }
        cy.summary.queued = absorbed.queued;
    }

    let vendors = detect_vendors(&inventory, config);
    cy.summary.vendors = vendors.len();
    let mut sources: Vec<SourceDef> = SOURCES.clone();
    if config.news {
        sources.extend(NEWS_SOURCES.iter().cloned());
    }
    sources.extend(vendor_sources(&vendors));
    let mut feeds: IndexMap<String, FeedState> = read_state(dir, "feeds.json").unwrap_or_default();
    let has_history = |feeds: &IndexMap<String, FeedState>, id: &str| feeds.get(id).is_some_and(|f| f.baselined == Some(true) || is_set(&f.cursor));
    let unread: IndexSet<String> = sources.iter().filter(|s| !has_history(&feeds, &s.id)).map(|s| s.id.clone()).collect();
    let mut options = PollOptions::new(deps.fetch, now);
    options.minutes = Some(config.poll_minutes);
    options.disabled = &config.disabled_sources;
    options.sources = Some(&sources);
    let poll = poll_sources(&mut feeds, &options);
    cy.summary.first_read = unread.iter().filter(|id| has_history(&feeds, id)).count();
    write_state(dir, "feeds.json", &feeds)?;
    cy.summary.polled = feeds.values().filter(|f| f.polled_at.as_deref() == Some(cy.at.as_str())).count();
    cy.summary.fresh = poll.items.len() + poll.cve_records.len();
    for (id, state) in &feeds {
        if let Some(error) = state.error.as_deref().filter(|e| !e.is_empty())
            && state.polled_at.as_deref() == Some(cy.at.as_str())
        {
            cy.summary.errors.push(format!("{id}: {error}"));
        }
    }
    let kev: HashSet<String> = feeds.get("cisa-kev").and_then(|f| f.seen.as_ref()).map(|seen| seen.keys().cloned().collect()).unwrap_or_default();

    cy.osv_phase(&poll, &kev, &records);
    cy.group_by_place();
    cy.node_phase(&poll);
    let cve_candidates = cy.cvelist_phase(&poll, &kev);
    cy.prose_phase(&poll, cve_candidates);
    cy.vendor_phase(&poll, &vendors, &rotation);
    cy.fix_phase();
    cy.dispatch()?;
    cy.secrets_phase();

    write_state(dir, "cases.json", &cy.cases)?;
    write_state(dir, "known.json", &cy.known)?;
    retry::write(dir, &cy.queue)?;
    write_state(dir, "osv-records.json", &*records.lock().unwrap_or_else(PoisonError::into_inner))?;
    cy.summary.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    write_state(dir, "last-cycle.json", &cy.summary)?;
    Ok(cy.summary)
}

/// Node's blog post and the security-wg index entries for one release are taken for the same release when the
/// case of one was first seen within this many days of the other.
const NODE_RELEASE_DAYS: i64 = 14;

/// What one half of a Node security release (the blog post, or the security-wg index entries) brings to the case of the other half.
struct NodeHalf {
    title: String,
    /// The prose items of the blog post, kept on the case so a feed that lists them again is recognised.
    items: Vec<ProseItem>,
    aliases: Vec<String>,
    urls: Vec<String>,
    sources: Vec<String>,
    targets: Vec<Target>,
    severity: Severity,
    fix_available: bool,
}

/// Target lines of two sources of one case, one per item: a line that names the fixed versions replaces the same
/// line without them (the index names them, the blog post does not).
fn merge_targets(a: &[String], b: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out: IndexMap<String, String> = IndexMap::new();
    for line in a.iter().cloned().chain(b) {
        let item = line.rsplit_once(" fixed in ").map_or(line.as_str(), |(head, _)| head).to_string();
        if line.contains(" fixed in ") || !out.contains_key(&item) {
            out.insert(item, line);
        }
    }
    out.into_values().collect()
}

/// Prose advisories carry no score; their headline usually says it ("Critical Vulnerabilities in PHP").
fn headline_severity(items: &[ProseItem]) -> Severity {
    if items.iter().any(|i| CRITICAL_WORD.is_match(&i.title)) {
        Severity::Critical
    } else if items.iter().any(|i| HIGH_WORD.is_match(&i.title)) {
        Severity::High
    } else {
        Severity::Unknown
    }
}

impl Cycle<'_, '_> {
    fn open(&mut self, c: Case) {
        self.summary.new_cases.push(c.key.clone());
        self.cases.insert(c.key.clone(), c);
    }

    /// OSV: a changed ecosystem, or a newer inventory, re-queries what we run. The first query of a
    /// family is the baseline: what is already vulnerable today. Its critical and high are told like new ones.
    fn osv_phase(&mut self, poll: &PollResult, kev: &HashSet<String>, records: &Mutex<IndexMap<String, OsvRecord>>) {
        let inventory = self.inventory;
        let families: IndexSet<&str> = inventory.items.iter().filter_map(|i| i.ecosystem.as_deref().filter(|e| !e.is_empty()).map(osv_family)).collect();
        let due: Vec<String> = families
            .into_iter()
            .filter(|f| {
                poll.osv_changed.iter().any(|c| c == f)
                    || self.known.osv_queried_at.get(*f).is_none_or(|queried| queried.is_empty() || queried.as_str() < inventory.collected_at.as_str())
            })
            .map(str::to_string)
            .collect();
        if due.is_empty() {
            return;
        }
        let hits = match osv_query(inventory, &due, self.deps.fetch) {
            Ok(hits) => hits,
            Err(e) => {
                record_error(self.config, &mut self.summary, "osv", &e);
                return;
            }
        };
        self.summary.osv_queried = due.clone();
        let mut work: Vec<Work> = Vec::new();
        for family in &due {
            let baseline = !is_set(&self.known.osv_queried_at.get(family).cloned());
            let seen = self.known.osv.entry(family.clone()).or_default();
            for hit in hits.values() {
                if !hit.items.iter().any(|item| item.ecosystem.as_deref().is_some_and(|e| !e.is_empty() && osv_family(e) == family)) {
                    continue;
                }
                let prior = seen.insert(hit.id.clone(), hit.modified.clone());
                if prior.as_deref() == Some(hit.modified.as_str()) {
                    continue;
                }
                let existing = by_alias(&self.cases, std::slice::from_ref(&hit.id)).and_then(|k| self.cases.get(&k));
                // A known match is re-read only when it changed and could now need action (a fix, exploitation).
                if prior.is_some() && !existing.is_some_and(|c| c.state == CaseState::Watch || (c.state == CaseState::Handled && !c.fix_available)) {
                    continue;
                }
                work.push(Work { hit: hit.clone(), family: family.clone(), baseline });
            }
            self.known.osv_queried_at.insert(family.clone(), self.at.clone());
        }
        let fetch = self.deps.fetch;
        let fetched = parallel_map(&work, 8, |w| record_for(records, &w.hit.id, &w.hit.modified, fetch));
        for (w, record) in work.iter().zip(fetched) {
            match record {
                Ok(record) => self.osv_hit(w, &record, kev),
                Err(e) => {
                    record_error(self.config, &mut self.summary, &format!("osv {}", w.hit.id), &e);
                    if let Some(seen) = self.known.osv.get_mut(&w.family) {
                        seen.shift_remove(&w.hit.id);
                    }
                }
            }
        }
    }

    /// One OSV hit: update the case that already covers it, or open one.
    fn osv_hit(&mut self, w: &Work, record: &OsvRecord, kev: &HashSet<String>) {
        let (hit, family) = (&w.hit, &w.family);
        let inventory = self.inventory;
        let at = self.at.clone();
        let aliases = unique(std::iter::once(hit.id.clone()).chain(record.aliases.iter().flatten().cloned()));
        let key = aliases.iter().find(|a| a.starts_with("CVE-")).cloned().unwrap_or_else(|| hit.id.clone());
        let fixes = osv_fixes(record, &hit.items);
        let mut targets: Vec<Target> = hit.items.iter().map(|item| target_for(item, &inventory.services, &self.config.priority)).collect();
        for t in &mut targets {
            t.fixed_in = Some(fixes.clone());
        }
        let severity = osv_severity(record);
        let exploited = aliases.iter().any(|a| kev.contains(a));
        let malicious = hit.id.starts_with("MAL-");
        let current = if self.cases.contains_key(&key) { Some(key.clone()) } else { by_alias(&self.cases, &aliases) };
        if let Some(current) = current {
            let Some(c) = self.cases.get_mut(&current) else { return };
            c.aliases = unique(c.aliases.iter().cloned().chain(aliases.iter().cloned()));
            c.osv_ids.get_or_insert_with(IndexMap::new).insert(hit.id.clone(), hit.modified.clone());
            c.targets = unique(c.targets.iter().cloned().chain(targets.iter().map(describe_target)));
            let mut affected = c.affected.take().unwrap_or_default();
            affected.extend(affected_of(&targets));
            affected.truncate(80);
            c.affected = Some(affected);
            c.places = merge_places(&c.places, &places_of(&targets));
            c.updated_at = at.clone();
            // Another database's record of the same CVE may rate it higher (PYSEC critical, GHSA high).
            if at_least(severity, c.severity) && severity != c.severity {
                c.reason = c.reason.replacen(c.severity.as_str(), severity.as_str(), 1);
                c.severity = severity;
            }
            if c.state == CaseState::Handled && !c.fix_available && !fixes.is_empty() {
                reopen(c, &mut self.summary, &at, format!("fix released: {}; apply it and remove the temporary mitigation", fixes.join(", ")));
            } else if c.state == CaseState::Watch {
                let decision = package_decision(severity, !fixes.is_empty(), exploited, &targets, malicious);
                if decision.state == CaseState::Pending {
                    c.state = decision.state;
                    c.reason = decision.reason;
                    c.severity = severity;
                    c.fix_available = !fixes.is_empty();
                    c.exploited = Some(exploited);
                }
            }
            return;
        }
        let decision = package_decision(severity, !fixes.is_empty(), exploited, &targets, malicious);
        // The baseline's lower findings stay in known.json and the baseline report, not as cases.
        if w.baseline && decision.state != CaseState::Pending {
            return;
        }
        let names = unique(hit.items.iter().map(|i| i.name.clone()));
        let title = record.summary.as_deref().filter(|s| !s.is_empty()).map_or_else(|| format!("{} in {}", hit.id, names.join(", ")), str::to_string);
        let mut c = new_case(key, CaseKind::Vulnerability, title, decision.state, decision.reason, severity, &at);
        c.exploited = Some(exploited);
        c.fix_available = !fixes.is_empty();
        c.aliases = aliases;
        c.urls = vec![format!("https://osv.dev/vulnerability/{}", hit.id)];
        c.sources = vec![format!("osv:{family}")];
        c.targets = targets.iter().map(describe_target).collect();
        c.affected = Some(affected_of(&targets));
        c.places = places_of(&targets);
        c.priority = Some(targets.iter().any(|t| t.priority));
        c.terms = Some(names);
        c.osv_ids = Some(IndexMap::from([(hit.id.clone(), hit.modified.clone())]));
        if fixes.is_empty() {
            let mut packages: IndexMap<String, WaitPackage> = IndexMap::new();
            for i in &hit.items {
                let ecosystem = i.ecosystem.clone().unwrap_or_default();
                packages.insert(format!("{ecosystem}\0{}", i.name), WaitPackage { ecosystem, name: i.name.clone() });
            }
            c.waiting_for = Some(vec![FixWait::Osv { id: hit.id.clone(), packages: packages.into_values().collect() }]);
        }
        if w.baseline {
            c.baseline = Some(true);
        }
        self.open(c);
    }

    /// Many advisories in one place (a new deployment, the install baseline): one case, and one response, per place.
    fn group_by_place(&mut self) {
        let mut by_place: IndexMap<String, Vec<String>> = IndexMap::new();
        for key in &self.summary.new_cases {
            let Some(c) = self.cases.get(key) else { continue };
            if c.state != CaseState::Pending || !c.sources.first().is_some_and(|s| s.starts_with("osv:")) {
                continue;
            }
            let mut keys: Vec<String> = c.places.iter().map(place_key).collect();
            keys.sort();
            by_place.entry(keys.join(" + ")).or_default().push(key.clone());
        }
        for (place, mut group) in by_place {
            if group.len() < 2 {
                continue;
            }
            // The lead names the case: an exploited advisory first (the "exploited" the group carries is its), then the most severe.
            group.sort_by(|a, b| {
                let (a, b) = (&self.cases[a.as_str()], &self.cases[b.as_str()]);
                (b.exploited == Some(true)).cmp(&(a.exploited == Some(true))).then(severity_order(a.severity).cmp(&severity_order(b.severity)))
            });
            let titles: Vec<String> = group.iter().map(|k| self.cases[k.as_str()].title.clone()).collect();
            let more = if group.len() > 3 { "; …" } else { "" };
            let title = format!("{} vulnerabilities in {place}: {}{more}", group.len(), titles.iter().take(3).cloned().collect::<Vec<_>>().join("; "));
            let lead_key = group[0].clone();
            let mut rest: Vec<Case> = Vec::new();
            for key in &group[1..] {
                if let Some(c) = self.cases.shift_remove(key) {
                    rest.push(c);
                }
            }
            let Some(lead) = self.cases.get_mut(&lead_key) else { continue };
            lead.title = title;
            for c in rest {
                lead.aliases = unique(lead.aliases.iter().cloned().chain(std::iter::once(c.key.clone())).chain(c.aliases.iter().cloned()));
                lead.urls = unique(lead.urls.iter().cloned().chain(c.urls.iter().cloned()));
                lead.targets = unique(lead.targets.iter().cloned().chain(c.targets.iter().cloned()));
                let mut affected = lead.affected.take().unwrap_or_default();
                affected.extend(c.affected.iter().flatten().cloned());
                affected.truncate(80);
                lead.affected = Some(affected);
                let mut ids = lead.osv_ids.take().unwrap_or_default();
                ids.extend(c.osv_ids.iter().flatten().map(|(k, v)| (k.clone(), v.clone())));
                lead.osv_ids = Some(ids);
                lead.waiting_for = Some(merge_waits(lead.waiting_for.as_deref(), c.waiting_for.as_deref().unwrap_or_default()));
                if lead.exploited != Some(true) {
                    lead.exploited = c.exploited;
                }
                // A fix for any of them is something to apply now; the rest stay in waitingFor.
                lead.fix_available = lead.fix_available || c.fix_available;
                self.summary.new_cases.retain(|key| *key != c.key);
            }
        }
    }

    /// The case of the other half of a Node security release: a vulnerability case about Node.js that `source` opened,
    /// first seen within `NODE_RELEASE_DAYS` of now, not found at install and not set aside (not affected, unsure,
    /// still judging). The closest in time when there are several.
    fn node_release_case(&self, source: &str) -> Option<String> {
        let window = NODE_RELEASE_DAYS * 86_400_000;
        self.cases
            .values()
            .filter(|c| {
                c.kind == CaseKind::Vulnerability
                    && c.baseline != Some(true)
                    && matches!(c.state, CaseState::Pending | CaseState::Handled | CaseState::Watch)
                    && c.sources.iter().any(|s| s == source)
                    && c.terms.iter().flatten().any(|t| t == "node.js")
            })
            .filter_map(|c| {
                let age = (self.now.as_millisecond() - parse_time(&c.first_seen)?.as_millisecond()).abs();
                (age <= window).then(|| (age, c.key.clone()))
            })
            .min_by_key(|(age, _)| *age)
            .map(|(_, key)| key)
    }

    /// The other half of a release joins the case of the first: it gains urls, sources, aliases, targets and places (without
    /// duplicates) and keeps its key. A handled case that had no fix is reopened as a fix announced, as for a prose item.
    fn join_node_release(&mut self, key: &str, half: NodeHalf) {
        let at = self.at.clone();
        let Some(c) = self.cases.get_mut(key) else { return };
        c.aliases = unique(c.aliases.iter().cloned().chain(half.aliases));
        c.urls = unique(c.urls.iter().cloned().chain(half.urls));
        c.sources = unique(c.sources.iter().cloned().chain(half.sources));
        c.targets = merge_targets(&c.targets, half.targets.iter().map(describe_target));
        c.places = merge_places(&c.places, &places_of(&half.targets));
        let mut affected = c.affected.take().unwrap_or_default();
        for a in affected_of(&half.targets) {
            if !affected.contains(&a) {
                affected.push(a);
            }
        }
        affected.truncate(80);
        c.affected = Some(affected);
        if half.targets.iter().any(|t| t.priority) {
            c.priority = Some(true);
        }
        if severity_order(half.severity) < severity_order(c.severity) {
            c.severity = half.severity;
        }
        if !half.items.is_empty() {
            let items = c.items.get_or_insert_with(Vec::new);
            for item in half.items {
                if !items.iter().any(|i| i.source == item.source && i.id == item.id) {
                    items.push(item);
                }
            }
        }
        c.updated_at = at.clone();
        if half.fix_available {
            if c.state == CaseState::Handled && !c.fix_available {
                reopen(c, &mut self.summary, &at, format!("fix announced: {}; apply it and remove the temporary mitigation", half.title));
            } else if !c.fix_available {
                c.fix_available = true;
                c.reason = c.reason.replace("; no fixed release named yet: mitigate until it ships", "");
            }
        }
    }

    /// Node's blog post for a release the security-wg index already opened a case for joins that case instead of
    /// opening its own (the index is read first in a cycle; the other order is `node_phase`'s). The items left over.
    fn join_node_blog(&mut self, unlinked: Vec<ProseItem>) -> Vec<ProseItem> {
        let is_blog = |i: &ProseItem| i.source == "node-security-blog";
        if !unlinked.iter().any(is_blog) {
            return unlinked;
        }
        let Some(key) = self.node_release_case("node-security-index") else { return unlinked };
        let blog: Vec<ProseItem> = unlinked.iter().filter(|i| is_blog(i)).cloned().collect();
        let Some(candidate) = prose_candidates(&blog, self.inventory, &self.config.priority).into_iter().next() else { return unlinked };
        let half = NodeHalf {
            title: blog[0].title.clone(),
            aliases: unique(blog.iter().flat_map(|i| i.cves.iter().cloned())),
            urls: unique(blog.iter().map(|i| i.url.clone())),
            sources: vec!["node-security-blog".to_string()],
            severity: headline_severity(&blog),
            fix_available: blog.iter().any(fix_named),
            targets: candidate.targets,
            items: blog,
        };
        self.join_node_release(&key, half);
        unlinked.into_iter().filter(|i| !is_blog(i)).collect()
    }

    /// Node security-wg index: entries matched by semver, grouped by release post. The first read is the baseline.
    fn node_phase(&mut self, poll: &PollResult) {
        struct Group {
            entries: Vec<NodeIndexEntry>,
            targets: IndexMap<String, Target>,
            severity: Severity,
        }
        let Some(index) = &poll.node_index else { return };
        let inventory = self.inventory;
        let at = self.at.clone();
        let keys: Vec<String> = index.keys().cloned().collect();
        let baseline = self.known.node_index.is_none();
        let fresh: Vec<String> = match &self.known.node_index {
            Some(known) => keys.iter().filter(|k| !known.contains(k)).cloned().collect(),
            None => keys.clone(),
        };
        self.known.node_index = Some(keys);
        let mut by_release: IndexMap<String, Group> = IndexMap::new();
        for hit in node_index_matches(index, inventory, Some(&fresh)) {
            let reference = hit.entry.reference.clone().or_else(|| hit.entry.cve.first().cloned()).unwrap_or_else(|| hit.key.clone());
            let group = by_release.entry(reference).or_insert_with(|| Group { entries: Vec::new(), targets: IndexMap::new(), severity: Severity::Unknown });
            group.entries.push(hit.entry.clone());
            for item in &hit.items {
                let mut t = target_for(item, &inventory.services, &self.config.priority);
                t.fixed_in = Some(vec![hit.entry.patched.clone()]);
                group.targets.insert(describe_target(&t), t);
            }
            if let Some(s) = Severity::parse(&hit.entry.severity.clone().unwrap_or_default().to_lowercase())
                && at_least(s, group.severity)
            {
                group.severity = s;
            }
        }
        for (reference, group) in by_release {
            let aliases: Vec<String> = group.entries.iter().flat_map(|e| e.cve.iter().cloned()).collect();
            let existing = self.cases.values().find(|c| c.urls.contains(&reference)).map(|c| c.key.clone()).or_else(|| by_alias(&self.cases, &aliases));
            let targets: Vec<Target> = group.targets.values().cloned().collect();
            if let Some(existing) = existing {
                if let Some(c) = self.cases.get_mut(&existing) {
                    c.aliases = unique(c.aliases.iter().cloned().chain(aliases.iter().cloned()));
                    c.targets = unique(c.targets.iter().cloned().chain(group.targets.keys().cloned()));
                    c.places = merge_places(&c.places, &places_of(&targets));
                    c.updated_at = at.clone();
                }
                continue;
            }
            let described: Vec<String> = group.entries.iter().map(|e| e.description.clone().unwrap_or_else(|| e.cve.join(" "))).take(3).collect();
            // The blog post of this release came first: its case takes the index entries.
            if !baseline && let Some(blog) = self.node_release_case("node-security-blog") {
                let half = NodeHalf {
                    title: format!("Node.js security release: {}", described.join("; ")),
                    items: Vec::new(),
                    aliases,
                    urls: vec![reference],
                    sources: vec!["node-security-index".to_string()],
                    targets,
                    severity: group.severity,
                    fix_available: true,
                };
                self.join_node_release(&blog, half);
                continue;
            }
            let notify = at_least(group.severity, Severity::High) || group.severity == Severity::Unknown;
            if baseline && !notify {
                continue;
            }
            let sev = group.severity.as_str();
            let (state, reason) = if notify {
                (CaseState::Pending, format!("Node {sev} vulnerabilities in installed versions"))
            } else {
                (CaseState::Watch, format!("{sev}: recorded, not notified"))
            };
            let key = aliases.first().cloned().unwrap_or_else(|| reference.clone());
            let mut c =
                new_case(key, CaseKind::Vulnerability, format!("Node.js security release: {}", described.join("; ")), state, reason, group.severity, &at);
            c.fix_available = true;
            c.aliases = aliases;
            c.urls = vec![reference];
            c.sources = vec!["node-security-index".to_string()];
            c.targets = group.targets.keys().cloned().collect();
            c.affected = Some(affected_of(&targets));
            c.places = places_of(&targets);
            c.priority = Some(targets.iter().any(|t| t.priority));
            c.terms = Some(vec!["node.js".to_string()]);
            if baseline {
                c.baseline = Some(true);
            }
            self.open(c);
        }
    }

    /// CVE List records new or changed since the last poll. A CVE a case already covers (by id or alias: OSV, KEV,
    /// another source) joins that case. Otherwise a readable range that puts something we run in the affected versions
    /// opens a case, and a product we run that the record names without a readable range goes on to the prose path
    /// (name match, classifier) as a candidate: never straight to a case.
    fn cvelist_phase(&mut self, poll: &PollResult, kev: &HashSet<String>) -> Vec<ProseCandidate> {
        let inventory = self.inventory;
        let at = self.at.clone();
        let mut candidates: Vec<ProseCandidate> = Vec::new();
        for record in poll.cve_records.iter().filter(|r| r.published) {
            let matched = cvelist::match_record(record, inventory);
            let exploited = record.exploited || kev.contains(&record.id);
            let targets: Vec<Target> = matched
                .affected
                .iter()
                .map(|(item, fixes)| {
                    let mut t = target_for(item, &inventory.services, &self.config.priority);
                    t.fixed_in = Some(fixes.clone());
                    t
                })
                .collect();
            let fixes = unique(matched.affected.iter().flat_map(|(_, f)| f.iter().cloned()));
            if let Some(key) = by_alias(&self.cases, std::slice::from_ref(&record.id)) {
                let Some(c) = self.cases.get_mut(&key) else { continue };
                c.urls = unique(c.urls.iter().cloned().chain(std::iter::once(cvelist::cve_org_url(&record.id))));
                c.sources = unique(c.sources.iter().cloned().chain(std::iter::once(cvelist::SOURCE.to_string())));
                c.updated_at = at.clone();
                if !targets.is_empty() {
                    c.targets = unique(c.targets.iter().cloned().chain(targets.iter().map(describe_target)));
                    let mut affected = c.affected.take().unwrap_or_default();
                    for a in affected_of(&targets) {
                        if !affected.contains(&a) {
                            affected.push(a);
                        }
                    }
                    affected.truncate(80);
                    c.affected = Some(affected);
                    c.places = merge_places(&c.places, &places_of(&targets));
                }
                if at_least(record.severity, c.severity) && record.severity != c.severity {
                    c.reason = c.reason.replacen(c.severity.as_str(), record.severity.as_str(), 1);
                    c.severity = record.severity;
                }
                if exploited && c.exploited != Some(true) {
                    c.exploited = Some(true);
                    if c.state == CaseState::Watch {
                        c.state = CaseState::Pending;
                        c.reason = "now listed as exploited in the wild (CISA)".to_string();
                    }
                }
                if c.state == CaseState::Handled && !c.fix_available && !fixes.is_empty() {
                    reopen(c, &mut self.summary, &at, format!("fix released: {}; apply it and remove the temporary mitigation", fixes.join(", ")));
                } else {
                    c.fix_available |= !fixes.is_empty();
                    if c.state == CaseState::Watch && !targets.is_empty() {
                        let decision = package_decision(c.severity, c.fix_available, c.exploited == Some(true), &targets, false);
                        if decision.state == CaseState::Pending {
                            c.state = decision.state;
                            c.reason = decision.reason;
                        }
                    }
                }
                continue;
            }
            if !targets.is_empty() {
                let decision = package_decision(record.severity, !fixes.is_empty(), exploited, &targets, false);
                let names = unique(targets.iter().map(|t| t.item.name.clone()));
                let title = cvelist::headline(record).map_or_else(|| format!("{} in {}", record.id, names.join(", ")), |t| format!("{}: {t}", record.id));
                let mut c = new_case(record.id.clone(), CaseKind::Vulnerability, title, decision.state, decision.reason, record.severity, &at);
                c.exploited = Some(exploited);
                c.fix_available = !fixes.is_empty();
                c.aliases = vec![record.id.clone()];
                c.urls = unique(std::iter::once(cvelist::cve_org_url(&record.id)).chain(record.references.iter().take(1).cloned()));
                c.sources = vec![cvelist::SOURCE.to_string()];
                c.targets = targets.iter().map(describe_target).collect();
                c.affected = Some(affected_of(&targets));
                c.places = places_of(&targets);
                c.priority = Some(targets.iter().any(|t| t.priority));
                c.terms = Some(names);
                self.open(c);
            } else if !matched.candidates.is_empty() {
                let targets: Vec<Target> = matched.candidates.iter().map(|i| target_for(i, &inventory.services, &self.config.priority)).collect();
                let terms = if matched.terms.is_empty() { unique(matched.candidates.iter().map(|i| i.name.clone())) } else { matched.terms.clone() };
                candidates.push(ProseCandidate { items: vec![cvelist::prose_item(record)], terms, targets });
            }
        }
        candidates
    }

    fn has_judge(&self) -> bool {
        self.deps.judge.is_some() || self.config.classifier.is_some()
    }

    /// The classifier, or the stand-in a test or replay gave.
    fn run_judge(&self, candidate: &ProseCandidate) -> Result<Verdict> {
        match (self.deps.judge, &self.config.classifier) {
            (Some(judge), _) => judge(candidate),
            (None, Some(classifier)) => judge(candidate, classifier, self.deps.fetch),
            (None, None) => bail!("no classifier configured"),
        }
    }

    /// Prose advisories: link to known cases by CVE; otherwise products we run → classifier (or name match without a key).
    fn prose_phase(&mut self, poll: &PollResult, cve_candidates: Vec<ProseCandidate>) {
        let inventory = self.inventory;
        let at = self.at.clone();
        let mut unlinked: Vec<ProseItem> = Vec::new();
        for item in poll.items.iter().filter(|i| !is_set(&i.vendor) && i.news != Some(true)) {
            let linked = if item.cves.is_empty() {
                self.cases.values().find(|c| c.items.iter().flatten().any(|i| i.source == item.source && i.id == item.id)).map(|c| c.key.clone())
            } else {
                by_alias(&self.cases, &item.cves)
            };
            let Some(linked) = linked else {
                if item.changed != Some(true) {
                    unlinked.push(item.clone());
                }
                continue;
            };
            let Some(c) = self.cases.get_mut(&linked) else { continue };
            c.urls = unique(c.urls.iter().cloned().chain(std::iter::once(item.url.clone())));
            c.sources = unique(c.sources.iter().cloned().chain(std::iter::once(item.source.clone())));
            c.updated_at = at.clone();
            if item.exploited == Some(true) && c.exploited != Some(true) {
                c.exploited = Some(true);
                if c.state == CaseState::Watch {
                    c.state = CaseState::Pending;
                    c.reason = "now listed as exploited in the wild (CISA KEV)".to_string();
                }
            }
            if c.state == CaseState::Handled && !c.fix_available && FIX_WORDS.is_match(&format!("{} {}", item.title, item.text)) {
                c.items.get_or_insert_with(Vec::new).push(item.clone());
                reopen(c, &mut self.summary, &at, format!("fix announced: {}; apply it and remove the temporary mitigation", item.title));
            }
        }
        let unlinked = self.join_node_blog(unlinked);
        let judging: Vec<String> =
            self.cases.values().filter(|c| c.state == CaseState::Judging && c.kind == CaseKind::Vulnerability).map(|c| c.key.clone()).collect();
        let mut candidates: Vec<(ProseCandidate, Option<String>)> =
            prose_candidates(&unlinked, inventory, &self.config.priority).into_iter().map(|c| (c, None)).collect();
        candidates.extend(cve_candidates.into_iter().map(|c| (c, None)));
        for key in judging {
            let c = &self.cases[key.as_str()];
            let items = c.items.clone().unwrap_or_default();
            let candidate = prose_candidates(&items, inventory, &self.config.priority).into_iter().next().unwrap_or_else(|| ProseCandidate {
                items: items.clone(),
                terms: c.terms.clone().unwrap_or_default(),
                targets: Vec::new(),
            });
            candidates.push((candidate, Some(key)));
        }
        for (candidate, existing) in candidates {
            // Only a new case reads its first item: an existing `judging` case with no items is still judged (the TS does).
            let first = candidate.items.first();
            let aliases = unique(candidate.items.iter().flat_map(|i| i.cves.iter().cloned()));
            let high_signal = candidate.items.iter().any(|i| i.high_signal);
            let mut c = match &existing {
                Some(key) => self.cases[key.as_str()].clone(),
                None => {
                    let Some(first) = first else { continue };
                    // Prose advisories carry no score; their headline usually says it ("Critical Vulnerabilities in PHP").
                    let severity = headline_severity(&candidate.items);
                    let key = aliases.first().cloned().unwrap_or_else(|| take_utf16(&format!("{}:{}", first.source, first.id), 120).to_string());
                    let mut c =
                        new_case(key, CaseKind::Vulnerability, first.title.clone(), CaseState::Judging, "awaiting the classifier".to_string(), severity, &at);
                    c.exploited = Some(candidate.items.iter().any(|i| i.exploited == Some(true)));
                    c.fix_available = candidate.items.iter().any(fix_named);
                    c.aliases = aliases;
                    c.urls = unique(candidate.items.iter().map(|i| i.url.clone()));
                    c.sources = unique(candidate.items.iter().map(|i| i.source.clone()));
                    c.targets = candidate.targets.iter().map(describe_target).collect();
                    c.affected = Some(affected_of(&candidate.targets));
                    c.places = places_of(&candidate.targets);
                    c.priority = Some(candidate.targets.iter().any(|t| t.priority));
                    c.items = Some(candidate.items.clone());
                    c.terms = Some(candidate.terms.clone());
                    c.high_signal = Some(high_signal);
                    c
                }
            };
            if existing.is_some() && candidate.items.iter().any(fix_named) {
                c.fix_available = true;
            }
            if existing.is_none() && self.cases.contains_key(&c.key) {
                continue;
            }
            let fail_open = if high_signal { Verdict::Affected } else { Verdict::Unsure };
            let mut verdict: Option<Verdict> = None;
            if !self.has_judge() {
                verdict = Some(fail_open);
            } else {
                match self.run_judge(&candidate) {
                    Ok(v) => verdict = Some(v),
                    Err(e) => {
                        c.judge_failures = Some(c.judge_failures.unwrap_or(0) + 1);
                        record_error(self.config, &mut self.summary, "classifier", &e);
                        // Fail open for high-signal sources: missing a real one costs more than a responder's look.
                        if c.judge_failures.unwrap_or(0) >= 3 {
                            verdict = Some(fail_open);
                        }
                    }
                }
            }
            c.updated_at = at.clone();
            let how = if self.has_judge() { "classifier" } else { "name match (no classifier key)" };
            let terms = candidate.terms.join(", ");
            match verdict {
                Some(Verdict::Affected) => {
                    c.state = CaseState::Pending;
                    c.reason = format!("{how}: affected ({terms})");
                }
                Some(Verdict::Unsure) if high_signal => {
                    c.state = CaseState::Pending;
                    c.reason = format!("{how}: unsure; high-signal source");
                }
                Some(Verdict::Unsure) => {
                    c.state = CaseState::Unsure;
                    c.reason = format!("{how}: unsure");
                }
                Some(Verdict::NotAffected) => {
                    c.state = CaseState::NotAffected;
                    c.reason = format!("{how}: not affected ({terms})");
                }
                None => {}
            }
            if !c.fix_available && c.state == CaseState::Pending {
                c.reason.push_str("; no fixed release named yet: mitigate until it ships");
            }
            if existing.is_some() {
                self.cases.insert(c.key.clone(), c);
            } else {
                self.open(c);
            }
        }
    }

    /// Vendor incidents: the vendor's own feeds and the news, about vendors the user uses. Security only.
    fn vendor_phase(&mut self, poll: &PollResult, vendors: &[UserVendor], rotation: &RotationMap) {
        let inventory = self.inventory;
        let at = self.at.clone();
        let fetch = self.deps.fetch;
        let judge_vendor = |vendor: &UserVendor, items: &[ProseItem]| -> Option<Result<String>> {
            match (self.deps.judge_vendor, &self.config.classifier) {
                (Some(judge), _) => Some(judge(vendor, items)),
                (None, Some(classifier)) => {
                    let candidate = crate::vendors::VendorCandidate { vendor: vendor.clone(), items: items.to_vec() };
                    Some(classify(classifier, VENDOR_LABELS, &vendor_instructions(&vendor.name), &vendor_input(&candidate), fetch))
                }
                (None, None) => None,
            }
        };
        let has_judge = self.deps.judge_vendor.is_some() || self.config.classifier.is_some();
        let items: Vec<ProseItem> = poll.items.iter().filter(|i| is_set(&i.vendor) || i.news == Some(true)).cloned().collect();
        for candidate in vendor_candidates(&items, vendors) {
            let (vendor, items) = (&candidate.vendor, &candidate.items);
            let Some(item) = items.first() else { continue };
            let id_slug = slug(&item.id);
            let tail = if id_slug.len() > 24 { &id_slug[id_slug.len() - 24..] } else { id_slug.as_str() };
            let key = format!("vendor:{}:{}", vendor.id, if tail.is_empty() { slug(&item.title) } else { tail.to_string() });
            if self.cases.contains_key(&key) {
                continue;
            }
            // Without a classifier key the name match plus the incident-word filter decides.
            let mut label = "security-incident".to_string();
            if let Some(result) = judge_vendor(vendor, items) {
                match result {
                    Ok(l) => label = l,
                    Err(e) => {
                        label = if is_set(&item.vendor) { "unsure" } else { "not-security" }.to_string();
                        record_error(self.config, &mut self.summary, "classifier", &e);
                    }
                }
            }
            // Only a confirmed incident opens a case. "Unsure" (or a classifier failure) is set aside, recorded but silent: a vendor's
            // own blog or security feed carries advice, programs and research next to the real incidents.
            let state = match label.as_str() {
                "security-incident" => CaseState::Pending,
                "unsure" => CaseState::Unsure,
                _ => CaseState::NotAffected,
            };
            let reason = format!("{}: {label}", if has_judge { "classifier" } else { "keyword match (no classifier key)" });
            let mut c = new_case(key, CaseKind::Vendor, format!("{}: {}", vendor.name, item.title), state, reason, Severity::Unknown, &at);
            c.vendor = Some(vendor.id.clone());
            c.aliases = item.cves.clone();
            c.urls = vec![item.url.clone()];
            c.sources = vec![item.source.clone()];
            c.targets = vendor.evidence.clone();
            c.places = vendor.places.clone();
            c.items = Some(items.clone());
            c.high_signal = Some(is_set(&item.vendor));
            c.at_risk = Some(rotation_for(vendor, inventory, rotation));
            self.open(c);
        }
    }

    /// Fix tracking: handled cases still waiting for a fix are checked every cycle (each wait at most every 30 min).
    fn fix_phase(&mut self) {
        let fetch = self.deps.fetch;
        let osv_fixed = |wait: &FixWait| -> Result<Vec<String>> {
            let FixWait::Osv { id, packages } = wait else { return Ok(Vec::new()) };
            let items: Vec<InventoryItem> = packages
                .iter()
                .map(|p| InventoryItem {
                    host: String::new(),
                    r#where: String::new(),
                    kind: crate::types::ItemKind::Package,
                    ecosystem: Some(p.ecosystem.clone()),
                    name: p.name.clone(),
                    version: String::new(),
                    path: None,
                    running: None,
                    dev: None,
                    collector: None,
                })
                .collect();
            Ok(osv_fixes(&osv_record(id, fetch)?, &items))
        };
        let keys: Vec<String> = self
            .cases
            .values()
            .filter(|c| c.state == CaseState::Handled && c.waiting_for.as_ref().is_some_and(|w| !w.is_empty()))
            .map(|c| c.key.clone())
            .collect();
        let json = |w: &FixWait| serde_json::to_string(w).unwrap_or_default();
        for key in keys {
            let Some(c) = self.cases.get_mut(&key) else { continue };
            if let Some(checked_at) = c.wait_checked_at.as_deref().and_then(parse_time)
                && self.now.as_millisecond() - checked_at.as_millisecond() < 30 * 60_000
            {
                continue;
            }
            c.wait_checked_at = Some(self.at.clone());
            let mut checked: IndexSet<String> = c.waits_checked.clone().unwrap_or_default().into_iter().collect();
            for wait in c.waiting_for.clone().unwrap_or_default() {
                let id = json(&wait);
                match check_wait(&wait, fetch, Some(&osv_fixed)) {
                    Ok(shipped) => {
                        let first = checked.insert(id);
                        let Some(shipped) = shipped.filter(|s| !s.is_empty()) else { continue };
                        if let Some(waits) = c.waiting_for.as_mut()
                            && let Some(at) = waits.iter().position(|w| *w == wait)
                        {
                            waits.remove(at);
                        }
                        // Met at its first check: the release was already out when the wait was recorded (the response knew of it), so nothing reopens.
                        if first {
                            continue;
                        }
                        // The shipped wait is done; any others are still checked after this round's response.
                        reopen(
                            c,
                            &mut self.summary,
                            &self.at,
                            format!("fix shipped: {} ({shipped}); apply it and remove the temporary mitigation", describe_wait(&wait)),
                        );
                        break;
                    }
                    Err(e) => record_error(self.config, &mut self.summary, &format!("fix check {key}"), &e),
                }
            }
            let remaining: Vec<String> = c.waiting_for.iter().flatten().map(json).collect();
            c.waits_checked = Some(checked.into_iter().filter(|id| remaining.contains(id)).collect());
        }
    }

    /// Dispatch, in batches. The cases that turn pending in one cycle are told together in one message, rated, the
    /// urgent ones on top. The responder then works through them (most serious first, maxPerCycle a cycle), and the
    /// batch's results come as one report once every response in it has finished.
    fn dispatch(&mut self) -> Result<()> {
        let (config, inventory) = (self.config, self.inventory);
        let dir = config.state_dir.as_path();
        let at = self.at.clone();
        let notify = &self.deps.notify;
        let mut pending: Vec<String> = self.cases.values().filter(|c| c.state == CaseState::Pending).map(|c| c.key.clone()).collect();
        let mut prepared: IndexMap<String, Prepared> = IndexMap::new();
        for key in &pending {
            let mut c = self.cases[key.as_str()].clone();
            let p = prepare_case(config, &mut c, inventory, &self.cases, self.now)?;
            self.cases.insert(key.clone(), c);
            prepared.insert(key.clone(), p);
        }
        pending.sort_by(|a, b| {
            let (a, b) = (&self.cases[a.as_str()], &self.cases[b.as_str()]);
            rating_order(rating_of(a))
                .cmp(&rating_order(rating_of(b)))
                .then(severity_order(a.severity).cmp(&severity_order(b.severity)))
                .then((b.exploited == Some(true)).cmp(&(a.exploited == Some(true))))
                .then((b.priority == Some(true)).cmp(&(a.priority == Some(true))))
        });
        let mut batches: Vec<Batch> = read_state(dir, "batches.json").unwrap_or_default();
        let unbatched: Vec<String> = pending
            .iter()
            .filter(|k| {
                let batch = &self.cases[k.as_str()].batch;
                !is_set(batch) || !batches.iter().any(|b| Some(&b.id) == batch.as_ref() && !is_set(&b.reported_at))
            })
            .cloned()
            .collect();
        if !unbatched.is_empty() {
            let digits: String = at.chars().filter(char::is_ascii_digit).collect();
            let stamp = digits.get(8..14).unwrap_or_default();
            let report = dir.join("reports").join(format!("{}-batch-{stamp}.md", local_date(self.now, &config.timezone)));
            let batch = Batch { id: at.clone(), keys: unbatched.clone(), report: lossy(&report), told_at: None, reported_at: None };
            for key in &unbatched {
                if let Some(c) = self.cases.get_mut(key) {
                    c.batch = Some(batch.id.clone());
                }
            }
            let body: Vec<String> = unbatched
                .iter()
                .map(|k| {
                    let c = &self.cases[k.as_str()];
                    format!("## {}: {}\n\n{}\n", rating_of(c).as_str(), c.title, case_notice(c, &prepared[k.as_str()].file).text)
                })
                .collect();
            batches.push(batch.clone());
            write_file_atomic(&report, &body.join("\n"))?;
            // What can't wait interrupts the user, one line each: what, where, what is being done. The rest waits for the agent in charge.
            for key in unbatched.iter().filter(|k| rating_of(&self.cases[k.as_str()]) == Rating::ActToday) {
                let c = &self.cases[key.as_str()];
                let p = &prepared[key.as_str()];
                let doing = if self.deps.respond.is_some() && c.kind == CaseKind::Vulnerability {
                    match p.mode {
                        Mode::Act => "working around it now".to_string(),
                        Mode::Update => "applying the fix now".to_string(),
                        Mode::Propose => "checking it now; nothing changes without you".to_string(),
                    }
                } else if let Some(at_risk) = c.at_risk.as_ref().filter(|a| !a.is_empty()) {
                    format!("rotate {} key(s) tied to it", at_risk.len())
                } else {
                    "nothing automatic: see its report".to_string()
                };
                let notice = Notice {
                    event: NotifyEvent::Urgent,
                    title: format!("Act today: {} in {}: {doing}", clip(&c.title, 120), place_list(c, 2)),
                    text: String::new(),
                    key: Some(c.key.clone()),
                    severity: Some(c.severity.as_str().to_string()),
                    urls: None,
                    report_path: Some(lossy(&p.report)),
                };
                if let Err(e) = send(notify, &notice) {
                    record_error(config, &mut self.summary, &format!("urgent notice {}", c.key), &e);
                }
            }
        }
        for b in batches.iter_mut().filter(|b| !is_set(&b.told_at)) {
            let members: Vec<&Case> = b.keys.iter().filter_map(|k| self.cases.get(k)).filter(|c| c.batch.as_deref() == Some(b.id.as_str())).collect();
            match send(notify, &batch_notice(b, &members, self.deps.respond.is_some())) {
                Ok(()) => b.told_at = Some(at.clone()),
                Err(e) => record_error(config, &mut self.summary, &format!("batch notice {}", b.id), &e),
            }
        }
        let mut responding = 0;
        let max_per_cycle = config.responder.as_ref().map_or(2.0, |r| r.max_per_cycle);
        let now = self.now;
        // The agent said it is out of quota until a time: nothing starts before it, new cases included.
        let paused = self.queue.paused(now);
        for key in &pending {
            let p = &prepared[key.as_str()];
            let outcome = (|| -> Result<()> {
                let c = &self.cases[key.as_str()];
                if let Some(respond) = self.deps.respond {
                    if responding as f64 >= max_per_cycle || paused {
                        return Ok(());
                    }
                    responding += 1;
                    // A newer event for a queued case replaces its retry rather than adding a second run.
                    self.queue.replace(key);
                    let started = respond(c, &p.file, p.mode, Run { batch: true, retry: false });
                    if let Some(c) = self.cases.get_mut(key) {
                        c.state = CaseState::Handled;
                        c.handled_by = Some(HandledBy::Responder);
                        c.handled_at = Some(at.clone());
                    }
                    if let Err(e) = started {
                        // It never started: queued like a run that did not finish, not tried again every cycle.
                        let reason = take_utf16(&redact(config, &format!("could not start the responder: {e:#}")), 300).to_string();
                        self.queue.fail(key, &reason, now, now);
                        self.summary.queued.push(key.clone());
                        if let Some(c) = self.cases.get_mut(key) {
                            c.dispatch_error = Some(reason);
                        }
                        record_error(config, &mut self.summary, &format!("dispatch {key}"), &e);
                        return Ok(());
                    }
                } else {
                    // Its batch's message told it; until that is sent, it stays pending.
                    if !batches.iter().find(|b| Some(&b.id) == c.batch.as_ref()).is_some_and(|b| is_set(&b.told_at)) {
                        bail!("its batch message was not sent yet");
                    }
                    if let Some(c) = self.cases.get_mut(key) {
                        c.state = CaseState::Handled;
                        c.handled_by = Some(HandledBy::Notice);
                        c.handled_at = Some(at.clone());
                    }
                    write_file_atomic(&p.report, &format!("{}\n", case_notice(&self.cases[key.as_str()], &p.file).text))?;
                }
                if let Some(c) = self.cases.get_mut(key) {
                    c.dispatch_error = None;
                }
                self.summary.dispatched.push(key.clone());
                Ok(())
            })();
            if let Err(e) = outcome {
                if let Some(c) = self.cases.get_mut(key) {
                    c.dispatch_error = Some(take_utf16(&redact(config, &e.to_string()), 300).to_string());
                }
                record_error(config, &mut self.summary, &format!("dispatch {key}"), &e);
            }
        }
        self.retry_queued(&mut responding, max_per_cycle);
        if let Some(entry) = self.queue.stuck(now)
            && let Err(e) = send(notify, &retry::stuck_notice(&entry, self.queue.entries.len()))
        {
            self.queue.blocked_told = None;
            record_error(config, &mut self.summary, "responder-blocked notice", &e);
        }
        let queue = &self.queue;
        let (cases, summary) = (&self.cases, &mut self.summary);
        report_batches(dir, cases, queue, &mut batches, notify, &at, &mut |place, e| record_error(config, summary, place, e));
        let month = 30 * 86_400_000;
        let kept: Vec<&Batch> = batches
            .iter()
            .filter(|b| {
                !is_set(&b.reported_at) || b.reported_at.as_deref().and_then(parse_time).is_some_and(|r| self.now.as_millisecond() - r.as_millisecond() < month)
            })
            .collect();
        write_state(dir, "batches.json", &kept)?;
        Ok(())
    }

    /// Starts the queued cases whose time has come, most urgent first, within what is left of `maxPerCycle`: a reset
    /// of the agent's limit does not fire every waiting case at once.
    fn retry_queued(&mut self, responding: &mut usize, max_per_cycle: f64) {
        let Some(respond) = self.deps.respond else { return };
        let (config, now) = (self.config, self.now);
        let running: HashSet<String> = read_responses(&config.state_dir).into_iter().filter(|r| r.state == ResponseState::Running).map(|r| r.key).collect();
        let mut due: Vec<(Case, String)> = self
            .queue
            .due(now)
            .iter()
            .filter(|e| !running.contains(&e.key))
            .filter_map(|e| self.cases.get(&e.key).filter(|c| c.state != CaseState::Pending).map(|c| (c.clone(), e.failed_at.clone())))
            .collect();
        due.sort_by(|(a, a_failed), (b, b_failed)| retry_order(a, b).then(a_failed.cmp(b_failed)));
        for (mut c, _) in due {
            if *responding as f64 >= max_per_cycle {
                break;
            }
            *responding += 1;
            let key = c.key.clone();
            let started = prepare_case(config, &mut c, self.inventory, &self.cases, now).and_then(|p| respond(&c, &p.file, p.mode, Run { batch: false, retry: true }));
            self.cases.insert(key.clone(), c);
            match started {
                Ok(()) => {
                    self.queue.started(&key, now);
                    self.summary.retried.push(key);
                }
                Err(e) => {
                    let reason = take_utf16(&redact(config, &format!("could not start the responder: {e:#}")), 300).to_string();
                    self.queue.fail(&key, &reason, now, now);
                    record_error(config, &mut self.summary, &format!("retry {key}"), &e);
                }
            }
        }
    }

    /// Secrets sitting where they shouldn't: told once each, never their values.
    fn secrets_phase(&mut self) {
        let mut told: IndexSet<String> = self.known.secrets.clone().unwrap_or_default().into_iter().collect();
        let fresh: Vec<SecretFinding> = self
            .inventory
            .secrets
            .iter()
            .filter(|s| s.exposure != Exposure::ContainerEnv && s.exposure != Exposure::CiSecret && !told.contains(&finding_key(s)))
            .cloned()
            .collect();
        if !fresh.is_empty() {
            match send(&self.deps.notify, &secrets_notice(&fresh)) {
                Ok(()) => {
                    told.extend(fresh.iter().map(finding_key));
                    self.summary.secrets_told = fresh.len();
                }
                Err(e) => record_error(self.config, &mut self.summary, "secrets notice", &e),
            }
        }
        self.known.secrets = Some(told.into_iter().collect());
    }
}

/// Where a prepared case's files are: its case file, the mode it will run in and where its report goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    pub file: PathBuf,
    pub mode: Mode,
    pub report: PathBuf,
}

/// Cases handled in the last week that share a term or an alias with `c`.
fn related_cases(cases: &IndexMap<String, Case>, c: &Case, now: Timestamp) -> Vec<Value> {
    let week_ago = now.as_millisecond() - 7 * 86_400_000;
    cases
        .values()
        .filter(|other| {
            other.key != c.key
                && other.handled_at.as_deref().and_then(parse_time).is_some_and(|handled| handled.as_millisecond() > week_ago)
                && (other.terms.iter().flatten().any(|term| c.terms.iter().flatten().any(|t| t == term))
                    || other.aliases.iter().any(|alias| c.aliases.contains(alias)))
        })
        .map(|other| {
            let mut o = Map::new();
            o.insert("key".into(), json!(other.key));
            o.insert("title".into(), json!(other.title));
            o.insert("state".into(), json!(other.state.as_str()));
            if let Some(report) = &other.report {
                o.insert("report".into(), json!(report));
            }
            if let Some(handled_at) = &other.handled_at {
                o.insert("handledAt".into(), json!(handled_at));
            }
            Value::Object(o)
        })
        .collect()
}

/// Runbooks written at install, matched by a place's name.
fn runbooks_for(config: &Config, c: &Case) -> Vec<String> {
    let Some(dir) = config.runbooks.as_ref().filter(|d| d.exists()) else { return Vec::new() };
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut files: Vec<String> = entries.filter_map(|e| e.ok()?.file_name().into_string().ok()).filter(|f| f.ends_with(".md")).collect();
    files.sort();
    let names: Vec<String> = c.places.iter().map(|p| place_name(&p.host, &p.r#where).to_lowercase()).collect();
    files
        .into_iter()
        .filter(|f| {
            let base = f[..f.len() - 3].to_lowercase();
            names.iter().any(|n| n.contains(&base) || base.contains(n.rsplit('/').next().unwrap_or(n)))
        })
        .map(|f| lossy(&dir.join(f)))
        .collect()
}

/// Rates a case for the user, names its report and writes the case file a responder (or the agent in charge) works from.
pub fn prepare_case(config: &Config, c: &mut Case, inventory: &Inventory, cases: &IndexMap<String, Case>, now: Timestamp) -> Result<Prepared> {
    let mode = case_mode(config, c, inventory);
    let file = case_path(&config.state_dir, &c.key);
    let report = report_path(config, &c.key, now);
    c.report = Some(lossy(&report));
    if c.kind == CaseKind::Vulnerability {
        let at_risk: Vec<SecretFinding> = secrets_at_risk(inventory, &c.places, &[]).into_iter().filter(|s| s.exposure != Exposure::CiSecret).collect();
        c.at_risk = Some(at_risk.iter().map(describe_secret).collect());
        c.assessment = Some(assess(&AssessInput {
            severity: c.severity,
            exploited: c.exploited == Some(true),
            malicious: c.aliases.iter().any(|a| a.starts_with("MAL-")),
            affected: c.affected.as_deref().unwrap_or_default(),
            inventory,
            at_risk: at_risk.len(),
        }));
    } else if config.responder.is_some() {
        // Reported, not confirmed: the classifier reads one headline, and a vendor named in it may be the attack's tool
        // rather than its subject. The responder reads the sources and checks the user's exposure; only it sends an urgent line.
        c.assessment = Some(Assessment {
            rating: Rating::ActThisWeek,
            why: "reported as a security incident at a vendor you use; the responder checks whether it touches you before anything is sent".to_string(),
        });
    } else {
        c.assessment = Some(match c.at_risk.as_ref().filter(|a| !a.is_empty()) {
            Some(at_risk) => Assessment {
                rating: Rating::ActToday,
                why: format!("a security incident at a vendor you use; {} of your keys or env vars belong to it or are stored there", at_risk.len()),
            },
            None => Assessment {
                rating: Rating::ActThisWeek,
                why: "a security incident at a vendor you use; no keys of yours were found tied to it, check your account there".to_string(),
            },
        });
    }
    let text = case_file(config, c, inventory, cases, mode, now);
    match (file.parent(), file.file_name().and_then(|n| n.to_str())) {
        (Some(parent), Some(name)) => write_state(parent, name, &text)?,
        _ => bail!("bad case file path {}", file.display()),
    }
    Ok(Prepared { file, mode, report })
}

/// The case file a responder works from: the case, its places' services, runbooks and related cases.
pub fn case_file(config: &Config, c: &Case, inventory: &Inventory, cases: &IndexMap<String, Case>, mode: Mode, now: Timestamp) -> Value {
    let places: HashSet<String> = c.places.iter().map(place_key).collect();
    let mut out = Map::new();
    out.insert("case".into(), serde_json::to_value(c).expect("a case serializes"));
    out.insert("mode".into(), json!(mode.as_str()));
    out.insert(
        "inventory".into(),
        json!({ "path": lossy(&config.state_dir.join("inventory.json")), "collectedAt": inventory.collected_at, "sources": inventory.sources }),
    );
    let services: Vec<_> = inventory.services.iter().filter(|s| places.contains(&format!("{} {}", s.host, s.r#where))).collect();
    out.insert("services".into(), serde_json::to_value(services).expect("services serialize"));
    out.insert("priority".into(), json!(config.priority));
    out.insert("actOn".into(), json!(config.responder.as_ref().map(|r| r.act_on.clone()).unwrap_or_default()));
    out.insert("runbooks".into(), json!(runbooks_for(config, c)));
    out.insert("related".into(), Value::Array(related_cases(cases, c, now)));
    if let Some(report) = &c.report {
        out.insert("report".into(), json!(report));
    }
    Value::Object(out)
}

/// The notice of one case, in full (the batch file holds one per case).
pub fn case_notice(c: &Case, file: &Path) -> Notice {
    let mut lines: Vec<String> = Vec::new();
    if c.kind == CaseKind::Vendor {
        lines.push(format!("{}. Where you use it:", c.reason));
        lines.extend(c.targets.iter().take(10).map(|t| format!("- {t}")));
        let at_risk = c.at_risk.as_deref().unwrap_or_default();
        lines.push(String::new());
        lines.push(if at_risk.is_empty() {
            "No keys of yours were found that belong to it.".to_string()
        } else {
            "Keys and env vars that belong to it or are stored there (rotate if the incident concerns credentials or customer data):".to_string()
        });
        lines.extend(at_risk.iter().take(30).map(|t| format!("- {t}")));
        lines.push(String::new());
        lines.extend(c.urls.iter().map(|u| format!("Source: {u}")));
    } else {
        let waiting = c.waiting_for.as_deref().unwrap_or_default();
        lines.push(format!(
            "{}{}{}. {}.",
            c.severity.as_str(),
            if c.exploited == Some(true) { ", exploited in the wild" } else { "" },
            if c.baseline == Some(true) { ", already present at install" } else { "" },
            c.reason
        ));
        let fix = match (c.fix_available, waiting.is_empty()) {
            (true, false) => "available for some of these; not yet for the rest",
            (true, true) => "available",
            (false, _) => "not released yet",
        };
        let waits =
            if waiting.is_empty() { String::new() } else { format!(" (waiting for {})", waiting.iter().map(describe_wait).collect::<Vec<_>>().join("; ")) };
        lines.push(format!("Fix: {fix}{waits}"));
        lines.push("Affected:".to_string());
        lines.extend(c.targets.iter().take(20).map(|t| format!("- {t}")));
        if c.targets.len() > 20 {
            lines.push(format!("- … {} more", c.targets.len() - 20));
        }
        if let Some(at_risk) = c.at_risk.as_ref().filter(|a| !a.is_empty()) {
            lines.push(String::new());
            lines.push("Secrets at these places (rotate if exploitation is suspected):".to_string());
            lines.extend(at_risk.iter().take(15).map(|t| format!("- {t}")));
        }
        lines.push(String::new());
        lines.extend(c.urls.iter().take(5).map(|u| format!("Advisory: {u}")));
        lines.push(format!("Case file: {}", file.display()));
    }
    let rated = c.assessment.as_ref().map(|a| format!("{}: {}", a.rating.as_str().to_uppercase(), a.why)).unwrap_or_default();
    let title = format!(
        "{}{}{}",
        if c.priority == Some(true) { "[priority] " } else { "" },
        c.assessment.as_ref().map(|a| format!("{}: ", a.rating.as_str())).unwrap_or_default(),
        c.title
    );
    // `[rated, ...lines].filter(Boolean)`: the blank separator lines go too.
    let text = std::iter::once(rated).chain(lines).filter(|l| !l.is_empty()).collect::<Vec<_>>().join("\n");
    Notice {
        event: NotifyEvent::Case,
        title: take_utf16(&title, 200).to_string(),
        text,
        key: Some(c.key.clone()),
        severity: Some(c.severity.as_str().to_string()),
        urls: Some(c.urls.clone()),
        report_path: c.report.clone(),
    }
}

/// Secrets sitting where they shouldn't: names, places and fingerprints, never values.
pub fn secrets_notice(findings: &[SecretFinding]) -> Notice {
    let mut by_place: IndexMap<String, Vec<&SecretFinding>> = IndexMap::new();
    for f in findings {
        by_place.entry(format!("{} {}", f.host, f.r#where)).or_default().push(f);
    }
    let mut lines = vec![
        format!(
            "{} secret(s) sit where they could be read by someone who shouldn't. Values are never shown; the fingerprint (first 8 hex of the SHA-256) tells copies apart.",
            findings.len()
        ),
        String::new(),
    ];
    for (place, list) in &by_place {
        lines.push(place.clone());
        for f in list.iter().take(15) {
            let line = f.line.filter(|l| *l != 0).map(|l| format!(":{l}")).unwrap_or_default();
            let fingerprint = f.fingerprint.as_deref().filter(|p| !p.is_empty()).map(|p| format!(" (fp {p})")).unwrap_or_default();
            lines.push(format!("- {} in {}{line}{fingerprint}: {}", f.name.as_deref().unwrap_or(&f.kind), f.location, f.risk));
        }
        if list.len() > 15 {
            lines.push(format!("- … {} more", list.len() - 15));
        }
    }
    lines.push(String::new());
    lines.push("Move each to a secret store or a file only its service can read, then rotate it: once exposed, assume it was copied.".to_string());
    Notice {
        event: NotifyEvent::Secrets,
        title: format!("{} exposed secret(s) found", findings.len()),
        text: lines.join("\n"),
        key: None,
        severity: None,
        urls: None,
        report_path: None,
    }
}

fn short_place(p: &Place) -> String {
    let name = place_name(&p.host, &p.r#where);
    name.strip_prefix("github repo:").map_or_else(|| name.clone(), str::to_string)
}

fn place_list(c: &Case, max: usize) -> String {
    let names = unique(c.places.iter().map(short_place));
    let more = if names.len() > max { format!(" +{} more", names.len() - max) } else { String::new() };
    format!("{}{more}", names.iter().take(max).cloned().collect::<Vec<_>>().join(", "))
}

/// `3 act today, 1 plan it`.
fn tally(ratings: &[Rating]) -> String {
    RANK.iter()
        .map(|r| (r, ratings.iter().filter(|x| *x == r).count()))
        .filter(|(_, n)| *n > 0)
        .map(|(r, n)| format!("{n} {}", r.as_str()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// An approximation of `localeCompare` for place names: punctuation, then digits, then letters (case-insensitive),
/// lower case before upper case on a tie.
fn locale_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let key = |c: char| -> (u8, char) {
        let lower = c.to_lowercase().next().unwrap_or(c);
        if c.is_alphabetic() {
            (2, lower)
        } else if c.is_numeric() {
            (1, c)
        } else {
            (0, c)
        }
    };
    a.chars().map(key).cmp(b.chars().map(key)).then_with(|| a.chars().map(char::is_uppercase).cmp(b.chars().map(char::is_uppercase)))
}

/// Lower-rated cases, counted per place: the message stays short; the batch file has each in full.
fn counted_by_place(list: &[&Case]) -> Vec<String> {
    let mut per: IndexMap<String, usize> = IndexMap::new();
    for c in list {
        for name in unique(c.places.iter().map(short_place)) {
            *per.entry(name).or_default() += 1;
        }
    }
    let mut counted: Vec<(String, usize)> = per.into_iter().collect();
    counted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| locale_cmp(&a.0, &b.0)));
    counted.into_iter().map(|(name, n)| format!("- {name}: {n}")).collect()
}

/// One message for a batch: act today and act this week in full on top, the rest counted per place.
pub fn batch_notice(b: &Batch, members: &[&Case], responding: bool) -> Notice {
    let mut lines: Vec<String> = Vec::new();
    for rating in RANK {
        let list: Vec<&Case> = members.iter().copied().filter(|c| c.assessment.as_ref().map(|a| a.rating) == Some(rating)).collect();
        if list.is_empty() {
            continue;
        }
        if !HIGHLIGHT.contains(&rating) {
            lines.push(format!("{} ({}), by place:", rating.as_str().to_uppercase(), list.len()));
            lines.extend(counted_by_place(&list));
            lines.push(String::new());
            continue;
        }
        lines.push(format!("{} ({})", rating.as_str().to_uppercase(), list.len()));
        for c in list {
            lines.push(format!("• {}{}", if c.priority == Some(true) { "[priority] " } else { "" }, clip(&c.title, 160)));
            lines.push(format!("  where: {}", place_list(c, 3)));
            lines.push(format!("  why: {}", c.assessment.as_ref().map(|a| a.why.as_str()).unwrap_or_default()));
            if c.kind == CaseKind::Vulnerability
                && let Some(first) = c.targets.first()
            {
                let more = if c.targets.len() > 1 { format!(" (+{} more)", c.targets.len() - 1) } else { String::new() };
                lines.push(format!("  {}{more}", clip(first, 200)));
            }
            lines.extend(c.at_risk.iter().flatten().take(10).map(|k| format!("  key: {k}")));
        }
        lines.push(String::new());
    }
    lines.push(
        if responding {
            "The responder works through them, most serious first; one report follows when all are done."
        } else {
            "Each case in full is in the batch file."
        }
        .to_string(),
    );
    lines.push(format!("Batch file: {}", b.report));
    let ratings: Vec<Rating> = members.iter().map(|c| rating_of(c)).collect();
    Notice {
        event: NotifyEvent::Case,
        title: format!("{} new case(s): {}", members.len(), tally(&ratings)),
        text: lines.join("\n"),
        key: None,
        severity: None,
        urls: None,
        report_path: Some(b.report.clone()),
    }
}

/// A case a response answered: its message, or why it did not finish.
#[derive(Debug, Clone)]
pub struct Answered<'a> {
    pub c: &'a Case,
    pub message: String,
    pub failed: Option<String>,
}

/// One report for a batch whose responses have all finished: each case's rating and message, the urgent ones in full.
pub fn batch_results(b: &Batch, answered: &[Answered]) -> Notice {
    let rated: Vec<(&Answered, Rating)> = answered.iter().filter(|a| a.failed.is_none()).map(|a| (a, final_rating(a.c, &a.message))).collect();
    let failed: Vec<&Answered> = answered.iter().filter(|a| a.failed.is_some()).collect();
    let mut lines: Vec<String> = Vec::new();
    for rating in RANK {
        let list: Vec<&&Answered> = rated.iter().filter(|(_, r)| *r == rating).map(|(a, _)| a).collect();
        if list.is_empty() {
            continue;
        }
        lines.push(format!("{} ({})", rating.as_str().to_uppercase(), list.len()));
        for a in list {
            let body: Vec<&str> = a.message.split('\n').map(str::trim).filter(|l| !l.is_empty()).collect();
            if HIGHLIGHT.contains(&rating) {
                lines.push(format!("• {} ({})", clip(&a.c.title, 160), place_list(a.c, 3)));
                lines.extend(body.iter().take(6).map(|l| format!("  {}", clip(l, 400))));
            } else {
                lines.push(format!("- {} ({}): {}", clip(&a.c.title, 100), place_list(a.c, 2), clip(body.first().copied().unwrap_or_default(), 200)));
            }
        }
        lines.push(String::new());
    }
    if !failed.is_empty() {
        lines.push(format!("QUEUED TO RETRY ({}): the responder did not finish; each runs again by itself, after the time shown", failed.len()));
        lines.extend(failed.iter().map(|a| format!("- {} {}: {}", a.c.key, clip(&a.c.title, 100), a.failed.as_deref().unwrap_or_default())));
        lines.push(String::new());
    }
    let dir = Path::new(&b.report).parent().map_or_else(|| ".".to_string(), lossy);
    lines.push(format!("Each report: {dir}"));
    let ratings: Vec<Rating> = rated.iter().map(|(_, r)| *r).collect();
    let unfinished = if failed.is_empty() { String::new() } else { format!(", {} queued to retry", failed.len()) };
    Notice {
        event: NotifyEvent::Report,
        title: format!("Results for {} case(s): {}{unfinished}", answered.len(), tally(&ratings)),
        text: lines.join("\n"),
        key: None,
        severity: None,
        urls: None,
        report_path: Some(b.report.clone()),
    }
}

/// Sends the results of every told batch whose cases are all handled and whose responses have all finished.
fn report_batches(
    dir: &Path,
    cases: &IndexMap<String, Case>,
    queue: &Queue,
    batches: &mut [Batch],
    notify: &Notifier,
    at: &str,
    error: &mut dyn FnMut(&str, &dyn Display),
) -> usize {
    let responses: IndexMap<String, ResponseRecord> = read_responses(dir).into_iter().map(|r| (r.key.clone(), r)).collect();
    let mut sent = 0;
    for b in batches.iter_mut().filter(|b| is_set(&b.told_at) && !is_set(&b.reported_at)) {
        let members: Vec<&Case> = b.keys.iter().filter_map(|k| cases.get(k)).filter(|c| c.batch.as_deref() == Some(b.id.as_str())).collect();
        if members.iter().any(|c| {
            c.state == CaseState::Pending
                || (c.handled_by == Some(HandledBy::Responder) && responses.get(&c.key).is_some_and(|r| r.state == ResponseState::Running))
        }) {
            continue;
        }
        let answered: Vec<Answered> = members
            .iter()
            .filter(|c| c.handled_by == Some(HandledBy::Responder))
            .map(|c| {
                let record = responses.get(&c.key);
                let report = c.report.as_deref().filter(|r| Path::new(r).exists()).and_then(|r| std::fs::read_to_string(r).ok()).unwrap_or_default();
                let failed = match queue.entries.get(&c.key) {
                    Some(e) => Some(format!("{}; next try {}", e.reason, e.next_at)),
                    None => record.filter(|r| r.state == ResponseState::Failed).map(|r| r.error.clone().unwrap_or_else(|| "failed".to_string())),
                };
                Answered { c, message: message_of(&report), failed }
            })
            .collect();
        let outcome = if answered.is_empty() { Ok(false) } else { send(notify, &batch_results(b, &answered)).map(|()| true) };
        match outcome {
            Ok(did_send) => {
                sent += usize::from(did_send);
                b.reported_at = Some(at.to_string());
            }
            Err(e) => error(&format!("batch report {}", b.id), &e),
        }
    }
    sent
}

/// For a one-shot cycle that waited for its responses: their batch reports now, not at the next run.
pub fn report_finished_batches(dir: &Path, notify: &Notifier, at: &str) -> Result<usize> {
    let cases: IndexMap<String, Case> = read_state(dir, "cases.json").unwrap_or_default();
    let mut batches: Vec<Batch> = read_state(dir, "batches.json").unwrap_or_default();
    let sent = report_batches(dir, &cases, &retry::read(dir), &mut batches, notify, at, &mut |_, _| {});
    write_state(dir, "batches.json", &batches)?;
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_post(title: &str, published: &str) -> ProseItem {
        serde_json::from_value(serde_json::json!({ "source": "node-security-blog", "id": "x", "title": title, "text": "", "url": "https://example.org/x", "published": published }))
            .expect("a prose item")
    }

    #[test]
    fn a_node_release_day_past_the_end_of_the_month_rolls_over_like_v8() {
        // `February 31, 2026` is 3 March: a post published on the 3rd names the release as out, one on the 2nd does not.
        assert!(node_released(&node_post("Tuesday, February 31, 2026 Security Releases", "2026-03-03T10:00:00Z")));
        assert!(!node_released(&node_post("Tuesday, February 31, 2026 Security Releases", "2026-03-02T10:00:00Z")));
        assert!(node_released(&node_post("Friday, April 31, 2026 Security Releases", "2026-05-01T00:00:00Z")));
        assert!(!node_released(&node_post("Friday, January 32, 2026 Security Releases", "2026-12-01T00:00:00Z")));
    }
}
