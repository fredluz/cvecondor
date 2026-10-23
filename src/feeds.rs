// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! Advisory sources. Every request is conditional (ETag / Last-Modified) or a
//! tiny Range read, so "nothing new" costs a 304 and no model.

use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use indexmap::IndexMap;
use jiff::Timestamp;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::cvelist::{self, CveRecord};
use crate::http::{Fetch, Request, Response};
use crate::name::USER_AGENT;
use crate::util;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    Prose,
    Kev,
    NodeIndex,
    OsvHead,
    /// The CVE List's delta log; the records it names are fetched one by one.
    CveList,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceDef {
    pub id: String,
    pub url: String,
    pub kind: SourceKind,
    /// Feeds that only carry security items skip the keyword filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_only: Option<bool>,
    /// High-signal sources wake the responder when the judge is unsure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub high_signal: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_minutes: Option<u32>,
    /// OSV bucket directory for osv-head sources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<String>,
    /// A vendor's own status page or security feed: its items are about that vendor; only security incidents pass (plain outages don't).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// General security news: an item counts only when it names one of the user's vendors, and only security incidents pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub news: Option<bool>,
}

impl SourceDef {
    /// A source with every optional field unset.
    pub fn new(id: impl Into<String>, url: impl Into<String>, kind: SourceKind) -> Self {
        Self { id: id.into(), url: url.into(), kind, security_only: None, high_signal: None, min_minutes: None, ecosystem: None, vendor: None, news: None }
    }
}

/// General security news, matched against the user's vendors (a hosting-platform breach rarely gets a CVE).
pub static NEWS_SOURCES: LazyLock<Vec<SourceDef>> = LazyLock::new(|| {
    let news =
        |id: &str, url: &str, min_minutes: u32| SourceDef { news: Some(true), min_minutes: Some(min_minutes), ..SourceDef::new(id, url, SourceKind::Prose) };
    vec![
        news("news:hacker-news", "https://hnrss.org/frontpage", 15),
        news("news:bleepingcomputer", "https://www.bleepingcomputer.com/feed/", 15),
        news("news:the-hacker-news", "https://feeds.feedburner.com/TheHackersNews", 15),
        news("news:securityweek", "https://www.securityweek.com/feed/", 15),
        news("news:krebs", "https://krebsonsecurity.com/feed/", 30),
    ]
});

pub static SOURCES: LazyLock<Vec<SourceDef>> = LazyLock::new(|| {
    let high = |id: &str, url: &str, kind: SourceKind| SourceDef { high_signal: Some(true), ..SourceDef::new(id, url, kind) };
    let secure = |id: &str, url: &str, kind: SourceKind| SourceDef { security_only: Some(true), ..high(id, url, kind) };
    let mut sources = vec![
        secure("cisa-kev", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", SourceKind::Kev),
        secure("cert-eu", "https://cert.europa.eu/publications/security-advisories-rss", SourceKind::Prose),
        secure("node-security-blog", "https://nodejs.org/en/feed/vulnerability.xml", SourceKind::Prose),
        SourceDef::new("node-security-index", "https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json", SourceKind::NodeIndex),
        SourceDef { min_minutes: Some(10), ..high("php-news", "https://www.php.net/feed.atom", SourceKind::Prose) },
        // nginx.org's news: security releases name the product only as `nginx-1.31.7`.
        SourceDef { min_minutes: Some(15), ..high("nginx-news", "https://nginx.org/index.rss", SourceKind::Prose) },
        SourceDef::new("bun-releases", "https://github.com/oven-sh/bun/releases.atom", SourceKind::Prose),
        SourceDef { min_minutes: Some(15), ..high("python-blog", "https://blog.python.org/feeds/posts/default", SourceKind::Prose) },
        // CA incidents (key compromise, distrust) are not CVEs; Mozilla's CA Program bugs carry them first.
        secure(
            "ca-incidents",
            "https://bugzilla.mozilla.org/rest/bug?product=CA%20Program&include_fields=id,summary,component,creation_time,keywords&order=bug_id%20DESC&limit=100",
            SourceKind::Prose,
        ),
    ];
    // The CVE List (cvelistV5). Not `cves/delta.json` (3 KB, but only the latest run: a poll that misses one loses
    // its changes) and not the hourly release zips (4 MB, up to an hour late): `cves/deltaLog.json` is the
    // cumulative log, newest run first, one run every 5-30 minutes. It is 30 MB, so it is read with a Range of its
    // first bytes (raw.githubusercontent.com honours Range and answers 304 to If-None-Match on the whole file),
    // and each changed record is its own small file there.
    sources.push(SourceDef::new(cvelist::SOURCE, "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json", SourceKind::CveList));
    for ecosystem in ["npm", "PyPI", "Ubuntu", "Debian", "Alpine", "crates.io", "Go", "Packagist", "RubyGems"] {
        sources.push(SourceDef {
            ecosystem: Some(ecosystem.to_string()),
            ..SourceDef::new(
                format!("osv:{ecosystem}"),
                format!("https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/modified_id.csv"),
                SourceKind::OsvHead,
            )
        });
    }
    sources
});

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeedState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub polled_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// osv-head: newest modified timestamp seen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// prose/kev: item id → content hash, so edits (an advisory gaining its fix) are seen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen: Option<IndexMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baselined: Option<bool>,
    /// items new in the last poll
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fresh: Option<usize>,
    /// cve-list: changed records not fetched yet (over the per-poll cap) or whose fetch failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<Vec<PendingRecord>>,
}

/// A CVE List record to fetch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PendingRecord {
    pub id: String,
    /// A record the log lists as new (a CVE just published), not an update of an old one.
    #[serde(default)]
    pub new: bool,
    /// Failed fetches so far.
    #[serde(default)]
    pub tries: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProseItem {
    pub source: String,
    pub id: String,
    pub title: String,
    pub text: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
    #[serde(default)]
    pub cves: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exploited: Option<bool>,
    #[serde(default)]
    pub high_signal: bool,
    /// An already-seen item whose text changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    /// From a vendor's own feed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// From a general news feed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub news: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NodeIndexEntry {
    #[serde(default)]
    pub cve: Vec<String>,
    #[serde(default)]
    pub vulnerable: String,
    #[serde(default)]
    pub patched: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overview: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PollResult {
    pub items: Vec<ProseItem>,
    pub node_index: Option<IndexMap<String, NodeIndexEntry>>,
    /// OSV ecosystems whose database changed since the last poll.
    pub osv_changed: Vec<String>,
    /// CVE List records new or changed since the last poll.
    pub cve_records: Vec<CveRecord>,
}

/// An entry of CISA's Known Exploited Vulnerabilities JSON.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct KevEntry {
    #[serde(rename = "cveID", default)]
    pub cve_id: String,
    #[serde(rename = "vendorProject", default)]
    pub vendor_project: String,
    #[serde(default)]
    pub product: String,
    #[serde(rename = "vulnerabilityName", default)]
    pub vulnerability_name: String,
    #[serde(rename = "dateAdded", default)]
    pub date_added: String,
    #[serde(rename = "shortDescription", default)]
    pub short_description: String,
    #[serde(rename = "requiredAction", default)]
    pub required_action: Option<String>,
    #[serde(rename = "knownRansomwareCampaignUse", default)]
    pub known_ransomware_campaign_use: Option<String>,
}

/// A vendor's status page or the news: security incidents only, so a plain outage or a maintenance window never alerts.
/// Case-insensitive, ASCII `\w` and `\b` as in the JS original.
pub static INCIDENT_WORDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i-u)\b(breach\w*|unauthori[sz]ed|compromis\w*|leak\w*|exposed (credentials?|secrets?|tokens?|keys?|data)|security (incident|issue|event|breach|vulnerability|update)|credentials?|secrets? (were|was|have been)|tokens? (were|was|have been)|(rotate|revok)\w* (your |all |their )?(api )?(keys?|tokens?|credentials?|secrets?)|malicious|hack(ed|ers?)|intrusion|data (exposure|incident|theft)|supply[- ]chain (attack|compromise)|ransomware|account takeover|CVE-\d{4}-\d+)\b",
    )
    .expect("valid regex")
});

/// `\b(security|vulnerab\w*|…)\b`: the keyword filter for feeds that carry more than security items.
static SECURITY_WORDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i-u)\b(security|vulnerab\w*|CVE-\d{4}-\d+|exploit\w*|compromis\w*|distrust\w*|malicious|remote code execution|RCE|advisory)\b")
        .expect("valid regex")
});

/// Mozilla CA Program bugs that matter. `.` is JS's (no line terminators); `\w` and `\b` are ASCII as in JS.
static CA_SEVERE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)compromis|private key|distrust|remov(?-u:\w)* [^\n\r\u2028\u2029]* from (NSS|the root store)|unauthori[sz]ed access|mis-?issu(?-u:\w)* [^\n\r\u2028\u2029]* (google|microsoft|apple|mozilla)(?-u:\b)",
    )
    .expect("valid regex")
});

static CDATA: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)<!\[CDATA\[(.*?)\]\]>").expect("valid regex"));
static TAG_MARKUP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^>]+>").expect("valid regex"));
/// JS `\s`: not Rust's White_Space (JS has U+FEFF and lacks U+0085).
static JS_SPACES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[\t\n\x0B\x0C\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}]+").expect("valid regex"));
static BLOCKS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<item(?-u:\b).*?</item>|<entry(?-u:\b).*?</entry>").expect("valid regex"));
static LINK_HREF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)<link[^>]*href="([^"]+)""#).expect("valid regex"));
static CVE_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"CVE-[0-9]{4}-[0-9]{4,}").expect("valid regex"));

/// The elements `parse_feed` reads, each compiled once: `<name ...>(content)</name>`, case-insensitive.
static TAGS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    ["link", "guid", "id", "title", "description", "content", "summary", "pubDate", "published", "updated"]
        .into_iter()
        .map(|name| (name, Regex::new(&format!(r"(?is)<{name}(?:\s[^>]*)?>(.*?)</{name}>")).expect("valid regex")))
        .collect()
});

fn is_js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{B}' | '\u{C}' | '\r' | ' ' | '\u{A0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}'
    )
}

/// `s.slice(0, units)`: JS counts UTF-16 code units; a character that would straddle the cut is dropped.
fn slice_utf16(s: &str, units: usize) -> &str {
    let mut used = 0;
    for (i, c) in s.char_indices() {
        used += c.len_utf16();
        if used > units {
            return &s[..i];
        }
    }
    s
}

fn decode(text: &str) -> String {
    let text = CDATA.replace_all(text, "$1");
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
}

/// Entities decoded twice (feeds escape their HTML once more), markup dropped, whitespace collapsed.
fn strip(html: &str) -> String {
    let text = decode(&decode(html));
    let text = TAG_MARKUP.replace_all(&text, " ");
    JS_SPACES.replace_all(&text, " ").trim_matches(is_js_space).to_string()
}

/// The inner text of the first `<name>` element, or "".
fn tag<'a>(xml: &'a str, name: &str) -> &'a str {
    let re = &TAGS.iter().find(|(n, _)| *n == name).expect("a known tag").1;
    re.captures(xml).and_then(|c| c.get(1)).map_or("", |m| m.as_str())
}

/// The CVE ids in `text`, each once, in order of appearance.
pub fn cve_ids(text: &str) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for m in CVE_ID.find_iter(text) {
        if !ids.iter().any(|id| id == m.as_str()) {
            ids.push(m.as_str().to_string());
        }
    }
    ids
}

/// The first 16 hex digits of the SHA-256 of `text`.
fn hash(text: &str) -> String {
    util::sha256_hex(text.as_bytes())[..16].to_string()
}

/// RSS 2.0 items and Atom entries, as plain text.
pub fn parse_feed(xml: &str, source: &SourceDef) -> Vec<ProseItem> {
    let vendor = source.vendor.as_deref().filter(|v| !v.is_empty());
    let news = source.news.unwrap_or(false);
    BLOCKS
        .find_iter(xml)
        .filter_map(|block| {
            let block = block.as_str();
            let mut link = strip(tag(block, "link"));
            if link.is_empty() {
                link = LINK_HREF.captures(block).map_or("", |c| c.get(1).map_or("", |m| m.as_str())).to_string();
            }
            let mut id = strip(tag(block, "guid"));
            if id.is_empty() {
                id = strip(tag(block, "id"));
            }
            if id.is_empty() {
                id.clone_from(&link);
            }
            let title = strip(tag(block, "title"));
            let body = [tag(block, "description"), tag(block, "content"), tag(block, "summary")].into_iter().find(|t| !t.is_empty()).unwrap_or("");
            let text = slice_utf16(&strip(body), 6000).to_string();
            let date = [tag(block, "pubDate"), tag(block, "published"), tag(block, "updated")].into_iter().find(|t| !t.is_empty()).unwrap_or("");
            let published = Some(strip(date)).filter(|d| !d.is_empty());
            let haystack = format!("{title} {text}");
            let filter: &Regex = if vendor.is_some() || news {
                &INCIDENT_WORDS
            } else if source.security_only.unwrap_or(false) {
                return (!id.is_empty()).then(|| make_item(source, id, title, text, link, published));
            } else {
                &SECURITY_WORDS
            };
            (!id.is_empty() && filter.is_match(&haystack)).then(|| make_item(source, id, title, text, link, published))
        })
        .collect()
}

fn make_item(source: &SourceDef, id: String, title: String, text: String, url: String, published: Option<String>) -> ProseItem {
    let cves = cve_ids(&format!("{title} {text}"));
    ProseItem {
        source: source.id.clone(),
        id,
        title,
        text,
        url,
        published,
        cves,
        exploited: None,
        high_signal: source.high_signal.unwrap_or(false),
        changed: None,
        vendor: source.vendor.clone(),
        news: source.news,
    }
}

/// CISA's Known Exploited Vulnerabilities catalogue; every entry is exploited by definition.
pub fn parse_kev(json: &str) -> Result<Vec<ProseItem>> {
    #[derive(Deserialize)]
    struct Kev {
        #[serde(default)]
        vulnerabilities: Option<Vec<KevEntry>>,
    }
    let data: Kev = serde_json::from_str(json).context("invalid KEV JSON")?;
    Ok(data
        .vulnerabilities
        .unwrap_or_default()
        .into_iter()
        .map(|v| ProseItem {
            source: "cisa-kev".to_string(),
            id: v.cve_id.clone(),
            title: format!("{} {}: {}", v.vendor_project, v.product, v.vulnerability_name),
            text: format!("{} Required action: {}", v.short_description, v.required_action.as_deref().unwrap_or("")).trim_matches(is_js_space).to_string(),
            url: format!("https://nvd.nist.gov/vuln/detail/{}", v.cve_id),
            published: Some(v.date_added),
            cves: vec![v.cve_id],
            exploited: Some(true),
            high_signal: true,
            changed: None,
            vendor: None,
            news: None,
        })
        .collect())
}

/// Mozilla CA Program bugs about a compromise, distrust or mis-issuance (or tagged `sec-vector`).
pub fn parse_ca_incidents(json: &str) -> Result<Vec<ProseItem>> {
    #[derive(Deserialize)]
    struct Bug {
        id: serde_json::Number,
        #[serde(default)]
        summary: String,
        #[serde(default)]
        component: String,
        #[serde(default)]
        creation_time: String,
        #[serde(default)]
        keywords: Option<Vec<String>>,
    }
    #[derive(Deserialize)]
    struct Bugs {
        #[serde(default)]
        bugs: Option<Vec<Bug>>,
    }
    let data: Bugs = serde_json::from_str(json).context("invalid bugzilla JSON")?;
    Ok(data
        .bugs
        .unwrap_or_default()
        .into_iter()
        .filter(|bug| CA_SEVERE.is_match(&bug.summary) || bug.keywords.as_ref().is_some_and(|k| k.iter().any(|w| w == "sec-vector")))
        .map(|bug| ProseItem {
            source: "ca-incidents".to_string(),
            id: bug.id.to_string(),
            title: format!("CA incident: {}", bug.summary),
            text: format!(
                "Mozilla CA Program bug {} ({}): {}. A CA key compromise or distrust affects every TLS client that trusts the CA through its own root store (Node, Bun, Python certifi, Electron apps, distro ca-certificates) until each ships an updated store.",
                bug.id, bug.component, bug.summary
            ),
            url: format!("https://bugzilla.mozilla.org/show_bug.cgi?id={}", bug.id),
            published: Some(bug.creation_time),
            cves: Vec::new(),
            exploited: None,
            high_signal: true,
            changed: None,
            vendor: None,
            news: None,
        })
        .collect())
}

/// What `poll_sources` needs besides the feed states.
pub struct PollOptions<'a> {
    pub fetch: &'a dyn Fetch,
    pub now: Timestamp,
    /// The poll interval in minutes (default 5); a source's own `min_minutes` can only lengthen it.
    pub minutes: Option<f64>,
    /// Source ids not to poll.
    pub disabled: &'a [String],
    /// The sources to poll (default `SOURCES`).
    pub sources: Option<&'a [SourceDef]>,
}

impl<'a> PollOptions<'a> {
    /// Every source, the default interval, nothing disabled.
    pub fn new(fetch: &'a dyn Fetch, now: Timestamp) -> Self {
        Self { fetch, now, minutes: None, disabled: &[], sources: None }
    }
}

/// Most feeds polled at once.
const POLL_THREADS: usize = 8;
/// A feed's `seen` map keeps this many ids (the newest); KEV keeps all.
const SEEN_KEPT: usize = 400;
/// The CVE List's log is read in growing ranges of its first bytes until one reaches back to the last run we saw.
const LOG_WINDOWS: [usize; 4] = [64 << 10, 512 << 10, 4 << 20, 16 << 20];
/// Most CVE List records fetched in one poll (a bulk update touches hundreds); the rest wait in `pending`.
const RECORDS_PER_POLL: usize = 300;
/// A record whose fetch keeps failing is dropped after this many tries.
const RECORD_TRIES: u32 = 5;
/// `pending` keeps at most this many records.
const PENDING_KEPT: usize = 5000;

/// What one source's poll found.
#[derive(Default)]
struct Found {
    items: Vec<ProseItem>,
    node_index: Option<IndexMap<String, NodeIndexEntry>>,
    osv_changed: Vec<String>,
    cve_records: Vec<CveRecord>,
}

/// The key order a JS object would have: array-index keys ascending first, then the rest as inserted.
/// State files written by the TS version are in that order, and trimming `seen` must drop the oldest ids.
fn js_key_order(keys: impl Iterator<Item = String>) -> Vec<String> {
    let (mut indexes, others): (Vec<(u32, String)>, Vec<String>) = {
        let mut indexes = Vec::new();
        let mut others = Vec::new();
        for key in keys {
            match key.parse::<u32>() {
                Ok(n) if n != u32::MAX && n.to_string() == key => indexes.push((n, key)),
                _ => others.push(key),
            }
        }
        (indexes, others)
    };
    indexes.sort_by_key(|(n, _)| *n);
    indexes.into_iter().map(|(_, key)| key).chain(others).collect()
}

/// Polls every due source once. Prose items are reported only when new or edited
/// since the last poll; a source's first successful poll records a baseline and
/// reports nothing.
pub fn poll_sources(states: &mut IndexMap<String, FeedState>, options: &PollOptions) -> PollResult {
    let now = options.now;
    let sources: &[SourceDef] = options.sources.unwrap_or(&SOURCES);
    let mut due: Vec<(&SourceDef, FeedState)> = Vec::new();
    for source in sources.iter().filter(|s| !options.disabled.contains(&s.id)) {
        let state = states.entry(source.id.clone()).or_default();
        let interval_ms = f64::max(f64::from(source.min_minutes.unwrap_or(0)), options.minutes.unwrap_or(5.0) - 0.5) * 60_000.0;
        let recent =
            state.polled_at.as_deref().and_then(util::parse_time).is_some_and(|at| ((now.as_millisecond() - at.as_millisecond()) as f64) < interval_ms);
        if recent && state.error.is_none() {
            continue;
        }
        due.push((source, state.clone()));
    }
    let polled = util::parallel_map(&due, POLL_THREADS, |(source, state)| {
        let mut state = state.clone();
        let mut found = Found::default();
        poll_one(source, &mut state, options.fetch, now, &mut found);
        (state, found)
    });
    let mut result = PollResult::default();
    for ((source, _), (state, found)) in due.iter().zip(polled) {
        states.insert(source.id.clone(), state);
        result.items.extend(found.items);
        if found.node_index.is_some() {
            result.node_index = found.node_index;
        }
        result.osv_changed.extend(found.osv_changed);
        result.cve_records.extend(found.cve_records);
    }
    result
}

/// One source's poll: updates `state` the way the request went (a failure keeps what was learned before it) and records the error.
fn poll_one(source: &SourceDef, state: &mut FeedState, fetch: &dyn Fetch, now: Timestamp, found: &mut Found) {
    state.polled_at = Some(util::iso(now));
    state.fresh = Some(0);
    if let Err(error) = poll_request(source, state, fetch, now, found) {
        state.error = Some(slice_utf16(&format!("{error:#}"), 300).to_string());
    }
}

fn poll_request(source: &SourceDef, state: &mut FeedState, fetch: &dyn Fetch, now: Timestamp, found: &mut Found) -> Result<()> {
    if source.kind == SourceKind::CveList {
        return poll_cvelist(source, state, fetch, now, found);
    }
    let mut request = Request::get(source.url.as_str()).header("User-Agent", USER_AGENT).timeout(Duration::from_secs(60));
    if source.kind == SourceKind::OsvHead {
        request = request.header("Range", "bytes=0-1023");
    }
    if let Some(etag) = state.etag.as_deref().filter(|e| !e.is_empty()) {
        request = request.header("If-None-Match", etag);
    }
    if let Some(modified) = state.last_modified.as_deref().filter(|m| !m.is_empty()) {
        request = request.header("If-Modified-Since", modified);
    }
    let response = fetch.fetch(request)?;
    state.status = Some(response.status);
    if response.status == 304 {
        state.ok_at = Some(util::iso(now));
        state.error = None;
        return Ok(());
    }
    if !response.ok() {
        bail!("HTTP {}", response.status);
    }
    let body = response.text();
    state.etag = response.header("etag").filter(|e| !e.is_empty()).map(str::to_string);
    state.last_modified = response.header("last-modified").filter(|m| !m.is_empty()).map(str::to_string);
    match source.kind {
        SourceKind::OsvHead => {
            let newest = body.split('\n').next().and_then(|line| line.split(',').next()).unwrap_or("");
            let year = newest.as_bytes().get(..5);
            if !year.is_some_and(|y| y[..4].iter().all(u8::is_ascii_digit) && y[4] == b'-') {
                bail!("unexpected modified_id.csv");
            }
            let ecosystem = source.ecosystem.clone();
            match state.cursor.as_deref().filter(|c| !c.is_empty()) {
                Some(cursor) => {
                    if newest > cursor {
                        found.osv_changed.extend(ecosystem);
                        state.fresh = Some(1);
                    }
                }
                // The first poll still queries: it is the baseline that later polls diff against.
                None => found.osv_changed.extend(ecosystem),
            }
            state.cursor = Some(newest.to_string());
        }
        SourceKind::NodeIndex => {
            found.node_index = Some(serde_json::from_str(&body).context("invalid node security index JSON")?);
        }
        SourceKind::Kev | SourceKind::Prose => {
            let items = match source.kind {
                SourceKind::Kev => parse_kev(&body)?,
                _ if source.id == "ca-incidents" => parse_ca_incidents(&body)?,
                _ => parse_feed(&body, source),
            };
            let seen = state.seen.get_or_insert_with(IndexMap::new);
            let mut fresh: Vec<ProseItem> = Vec::new();
            for mut item in items {
                let digest = hash(&format!("{}\n{}", item.title, item.text));
                let before = seen.get(&item.id).map(String::as_str);
                if before == Some(digest.as_str()) {
                    continue;
                }
                if before.is_some_and(|b| !b.is_empty()) {
                    item.changed = Some(true);
                }
                seen.insert(item.id.clone(), digest);
                fresh.push(item);
            }
            // Keep the newest few hundred ids; KEV keeps all (its ids are the catalogue).
            if source.kind != SourceKind::Kev && seen.len() > SEEN_KEPT {
                let excess = seen.len() - SEEN_KEPT;
                for key in js_key_order(seen.keys().cloned()).into_iter().take(excess) {
                    seen.shift_remove(&key);
                }
            }
            if state.baselined.unwrap_or(false) {
                state.fresh = Some(fresh.len());
                found.items.extend(fresh);
            }
            state.baselined = Some(true);
        }
        SourceKind::CveList => bail!("the CVE List is polled by poll_cvelist"),
    }
    state.ok_at = Some(util::iso(now));
    state.error = None;
    Ok(())
}

/// One run of the CVE List's publisher, as `deltaLog.json` lists it.
#[derive(Debug, Deserialize)]
struct DeltaRun {
    #[serde(rename = "fetchTime")]
    fetch_time: String,
    #[serde(default)]
    new: Vec<DeltaRef>,
    #[serde(default)]
    updated: Vec<DeltaRef>,
}

#[derive(Debug, Deserialize)]
struct DeltaRef {
    #[serde(rename = "cveId")]
    cve_id: String,
}

/// The runs at the start of the log (a JSON array of objects): the complete ones, and the `fetchTime` of the one a
/// ranged read cut off, which still tells how far back the read reached.
fn parse_delta_head(text: &str) -> (Vec<DeltaRun>, Option<String>) {
    let (mut depth, mut start, mut in_string, mut escaped) = (0usize, None::<usize>, false, false);
    let mut runs = Vec::new();
    for (i, b) in text.bytes().enumerate() {
        if in_string {
            match b {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth == 2 && b == b'{' {
                    start = Some(i);
                }
            }
            b'}' | b']' => {
                if depth == 2
                    && b == b'}'
                    && let Some(from) = start.take()
                    && let Ok(run) = serde_json::from_str::<DeltaRun>(&text[from..=i])
                {
                    runs.push(run);
                }
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    let cut = start.and_then(|from| {
        let rest = &text[from..];
        let value = &rest[rest.find("\"fetchTime\"")? + "\"fetchTime\"".len()..];
        let value = &value[value.find('"')? + 1..];
        Some(value[..value.find('"')?].to_string())
    });
    (runs, cut)
}

/// Whether a ranged response reaches the end of the file.
fn reaches_end(response: &Response, window: usize) -> bool {
    let range = response.header("content-range").and_then(|r| r.rsplit_once('/'));
    match range.and_then(|(span, total)| Some((span.rsplit('-').next()?.parse::<u64>().ok()?, total.parse::<u64>().ok()?))) {
        Some((end, total)) => end + 1 >= total,
        None => response.body.len() < window,
    }
}

/// `cves/<year>/<number without its last three digits>xxx/<id>.json` under the log's own directory.
fn record_url(base: &str, id: &str) -> Option<String> {
    let (year, number) = id.strip_prefix("CVE-")?.split_once('-')?;
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if year.len() != 4 || number.len() < 4 || !digits(year) || !digits(number) {
        return None;
    }
    Some(format!("{base}{year}/{}xxx/{id}.json", &number[..number.len() - 3]))
}

enum Fetched {
    Record(Box<CveRecord>),
    /// Not worth another try: the id is not a CVE id or the record does not parse.
    Dropped,
    Retry,
}

fn fetch_record(base: &str, id: &str, fetch: &dyn Fetch) -> Fetched {
    let Some(url) = record_url(base, id) else { return Fetched::Dropped };
    match fetch.fetch(Request::get(url).header("User-Agent", USER_AGENT).timeout(Duration::from_secs(30))) {
        Ok(response) if response.ok() => cvelist::parse_record(&response.text()).map_or(Fetched::Dropped, |record| Fetched::Record(Box::new(record))),
        _ => Fetched::Retry,
    }
}

/// The CVE List: `deltaLog.json` read with a conditional Range request (a 304 when no run happened), the records
/// of the runs since the last poll fetched one by one. The first read only records where the log stands.
fn poll_cvelist(source: &SourceDef, state: &mut FeedState, fetch: &dyn Fetch, now: Timestamp, found: &mut Found) -> Result<()> {
    let Some(base) = source.url.strip_suffix("deltaLog.json") else { bail!("unexpected CVE List log URL") };
    let cursor = state.cursor.clone().filter(|c| !c.is_empty());
    let mut log: Option<(Vec<DeltaRun>, Option<String>)> = None;
    for (attempt, window) in LOG_WINDOWS.into_iter().enumerate() {
        let mut request = Request::get(source.url.as_str())
            .header("User-Agent", USER_AGENT)
            .header("Range", format!("bytes=0-{}", window - 1))
            .timeout(Duration::from_secs(60));
        if attempt == 0
            && let Some(etag) = state.etag.as_deref().filter(|e| !e.is_empty())
        {
            request = request.header("If-None-Match", etag);
        }
        let response = fetch.fetch(request)?;
        state.status = Some(response.status);
        if response.status == 304 {
            break;
        }
        if !response.ok() {
            bail!("HTTP {}", response.status);
        }
        let (runs, cut) = parse_delta_head(&response.text());
        let reached = match &cursor {
            None => !runs.is_empty(),
            Some(c) => runs.iter().map(|r| r.fetch_time.as_str()).chain(cut.as_deref()).any(|t| t <= c.as_str()),
        };
        let done = reached || reaches_end(&response, window);
        log = Some((runs, response.header("etag").filter(|e| !e.is_empty()).map(str::to_string)));
        if done {
            break;
        }
    }
    let mut queue: Vec<PendingRecord> = state.pending.clone().unwrap_or_default();
    if let Some((mut runs, etag)) = log {
        if runs.is_empty() {
            bail!("unexpected deltaLog.json");
        }
        runs.sort_by(|a, b| a.fetch_time.cmp(&b.fetch_time));
        let newest = runs.last().map(|r| r.fetch_time.clone()).unwrap_or_default();
        if let Some(cursor) = &cursor {
            let mut changed: IndexMap<&str, bool> = IndexMap::new();
            for run in runs.iter().filter(|r| r.fetch_time.as_str() > cursor.as_str()) {
                for (list, new) in [(&run.new, true), (&run.updated, false)] {
                    for r in list {
                        *changed.entry(r.cve_id.as_str()).or_insert(false) |= new;
                    }
                }
            }
            for (id, new) in changed {
                match queue.iter_mut().find(|p| p.id == id) {
                    Some(p) => p.new |= new,
                    None => queue.push(PendingRecord { id: id.to_string(), new, tries: 0 }),
                }
            }
        }
        state.etag = etag;
        state.last_modified = None;
        if cursor.as_deref().is_none_or(|c| newest.as_str() > c) {
            state.cursor = Some(newest);
        }
        state.baselined = Some(true);
    }
    // A new CVE before an update of an old one; otherwise in the order they came.
    queue.sort_by_key(|p| !p.new);
    let rest = queue.split_off(queue.len().min(RECORDS_PER_POLL));
    let fetched = util::parallel_map(&queue, POLL_THREADS, |p| fetch_record(base, &p.id, fetch));
    let mut pending: Vec<PendingRecord> = Vec::new();
    for (p, result) in queue.into_iter().zip(fetched) {
        match result {
            Fetched::Record(record) => found.cve_records.push(*record),
            Fetched::Retry if p.tries + 1 < RECORD_TRIES => pending.push(PendingRecord { tries: p.tries + 1, ..p }),
            Fetched::Retry | Fetched::Dropped => {}
        }
    }
    pending.extend(rest);
    pending.truncate(PENDING_KEPT);
    state.pending = Some(pending).filter(|p| !p.is_empty());
    state.fresh = Some(found.cve_records.len());
    state.ok_at = Some(util::iso(now));
    state.error = None;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::http::Response;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join(name)).expect("the fixture exists")
    }

    fn source(id: &str, kind: SourceKind) -> SourceDef {
        SourceDef::new(id, format!("https://example.com/{id}"), kind)
    }

    fn ok(body: &str) -> Response {
        Response { status: 200, headers: Vec::new(), body: body.as_bytes().to_vec() }
    }

    fn feed(items: &[(&str, &str)]) -> String {
        let items: String =
            items.iter().map(|(guid, title)| format!("<item><guid>{guid}</guid><title>{title}</title><description>d</description></item>")).collect();
        format!("<rss><channel>{items}</channel></rss>")
    }

    fn at(s: &str) -> Timestamp {
        s.parse().expect("a timestamp")
    }

    #[test]
    fn parse_feed_reads_cert_eu_items_as_plain_text() {
        let source = SourceDef { security_only: Some(true), high_signal: Some(true), ..source("cert-eu", SourceKind::Prose) };
        let items = parse_feed(&fixture("cert-eu-2026-10-21.xml"), &source);
        assert_eq!(items.len(), 2);
        let php = &items[0];
        assert_eq!(php.title, "2026-018: Critical Vulnerabilities in PHP");
        assert_eq!(php.url, "https://cert.europa.eu/publications/security-advisories/2026-018/");
        assert_eq!(php.id, "security-advisories-10955");
        assert_eq!(php.published.as_deref(), Some("Wed, 21 Oct 2026 17:20:18 CEST"));
        assert!(php.text.starts_with("On 20 October 2026, the PHP project announced"));
        assert!(php.text.contains("remote code execution. The PHP team released"), "the escaped <br> became a space: {}", php.text);
        assert!(!php.text.contains('<') && !php.text.contains("&lt;"));
        assert!(php.high_signal);
        assert_eq!(php.vendor, None);
    }

    #[test]
    fn parse_feed_unwraps_cdata_and_filters_by_keyword() {
        let xml = fixture("node-vulnerability-2026-10-21.xml");
        let node = SourceDef { security_only: Some(true), ..source("node-security-blog", SourceKind::Prose) };
        let items = parse_feed(&xml, &node);
        let titles: Vec<&str> = items.iter().map(|i| i.title.as_str()).collect();
        assert_eq!(titles, ["Wednesday, October 21, 2026 Security Releases", "Wednesday, July 29, 2026 Security Releases"]);
        assert_eq!(items[0].id, "/blog/vulnerability/october-2026-security-releases?1792620000000");
        assert_eq!(items[0].published.as_deref(), Some("Wed, 21 Oct 2026 22:00:00 GMT"));
        // Without securityOnly the keyword filter applies; "Security" in both titles passes it, a vendor feed wants an incident word.
        assert_eq!(parse_feed(&xml, &source("any", SourceKind::Prose)).len(), 2);
        assert!(parse_feed(&xml, &SourceDef { vendor: Some("acme".into()), ..source("status", SourceKind::Prose) }).is_empty());
    }

    #[test]
    fn parse_feed_reads_atom_entries_and_finds_cves() {
        let xml = r#"<feed><entry><id>tag:x,1</id><title>Fix for CVE-2026-1234 and CVE-2026-1234, CVE-2026-99999</title>
            <link rel="alternate" href="https://example.com/a"/><updated>2026-10-21T10:00:00Z</updated><content type="html">&lt;p&gt;An exploit exists&lt;/p&gt;</content></entry></feed>"#;
        let items = parse_feed(xml, &source("atom", SourceKind::Prose));
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, "tag:x,1");
        assert_eq!(items[0].url, "https://example.com/a");
        assert_eq!(items[0].text, "An exploit exists");
        assert_eq!(items[0].published.as_deref(), Some("2026-10-21T10:00:00Z"));
        assert_eq!(items[0].cves, ["CVE-2026-1234", "CVE-2026-99999"]);
    }

    #[test]
    fn parse_ca_incidents_keeps_the_key_compromise_bug() {
        let items = parse_ca_incidents(&fixture("bugzilla-ca-2083449.json")).expect("parses");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, "2083449");
        assert_eq!(items[0].title, "CA incident: eMudhra: Private key compromise of Intermediate Certificates");
        assert_eq!(items[0].url, "https://bugzilla.mozilla.org/show_bug.cgi?id=2083449");
        assert_eq!(items[0].published.as_deref(), Some("2026-10-18T12:06:03Z"));
        assert!(items[0].text.starts_with("Mozilla CA Program bug 2083449 (CA Certificate Compliance): eMudhra: Private key compromise"));
        let routine = r#"{"bugs":[{"id":1,"summary":"Delayed audit report","component":"CA Certificate Compliance","creation_time":"2026-10-01T00:00:00Z","keywords":[]}]}"#;
        assert!(parse_ca_incidents(routine).expect("parses").is_empty());
    }

    #[test]
    fn parse_kev_marks_every_entry_exploited() {
        let json = r#"{"vulnerabilities":[{"cveID":"CVE-2026-1","vendorProject":"Acme","product":"Widget","vulnerabilityName":"Widget RCE","dateAdded":"2026-10-20","shortDescription":"Bad.","requiredAction":"Patch."}]}"#;
        let items = parse_kev(json).expect("parses");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "Acme Widget: Widget RCE");
        assert_eq!(items[0].text, "Bad. Required action: Patch.");
        assert_eq!(items[0].exploited, Some(true));
        assert_eq!(items[0].cves, ["CVE-2026-1"]);
    }

    #[test]
    fn first_poll_baselines_and_the_second_reports_only_the_new_item() {
        let body = Mutex::new(feed(&[("a", "Security release one")]));
        let fetch = |_: Request| Ok(ok(&body.lock().expect("lock")));
        let feeds = [source("feed", SourceKind::Prose)];
        let mut states = IndexMap::new();
        let first = poll_sources(&mut states, &PollOptions { sources: Some(&feeds), ..PollOptions::new(&fetch, at("2026-10-21T10:00:00Z")) });
        assert!(first.items.is_empty(), "the first read is the baseline");
        assert_eq!(states["feed"].baselined, Some(true));
        assert_eq!(states["feed"].fresh, Some(0));
        assert_eq!(states["feed"].polled_at.as_deref(), Some("2026-10-21T10:00:00.000Z"));

        *body.lock().expect("lock") = feed(&[("a", "Security release one"), ("b", "Security release two")]);
        // Inside the interval nothing is polled.
        let early = poll_sources(&mut states, &PollOptions { sources: Some(&feeds), ..PollOptions::new(&fetch, at("2026-10-21T10:02:00Z")) });
        assert!(early.items.is_empty());
        assert_eq!(states["feed"].polled_at.as_deref(), Some("2026-10-21T10:00:00.000Z"));

        let second = poll_sources(&mut states, &PollOptions { sources: Some(&feeds), ..PollOptions::new(&fetch, at("2026-10-21T10:10:00Z")) });
        let ids: Vec<&str> = second.items.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, ["b"]);
        assert_eq!(second.items[0].changed, None);
        assert_eq!(states["feed"].fresh, Some(1));

        // An edited item is reported again, marked changed.
        *body.lock().expect("lock") = feed(&[("a", "Security release one: fixed in 2.0"), ("b", "Security release two")]);
        let third = poll_sources(&mut states, &PollOptions { sources: Some(&feeds), ..PollOptions::new(&fetch, at("2026-10-21T10:20:00Z")) });
        assert_eq!(third.items.len(), 1);
        assert_eq!((third.items[0].id.as_str(), third.items[0].changed), ("a", Some(true)));
    }

    #[test]
    fn requests_are_conditional_and_a_failure_is_recorded_then_retried_at_once() {
        let seen: Mutex<Vec<Vec<(String, String)>>> = Mutex::new(Vec::new());
        let answers = Mutex::new(vec![
            Response { status: 200, headers: vec![("etag".into(), "\"v1\"".into())], body: feed(&[("a", "Security one")]).into_bytes() },
            Response { status: 304, headers: Vec::new(), body: Vec::new() },
            Response { status: 503, headers: Vec::new(), body: Vec::new() },
            ok(&feed(&[("a", "Security one")])),
        ]);
        let fetch = |req: Request| {
            seen.lock().expect("lock").push(req.headers.clone());
            Ok(answers.lock().expect("lock").remove(0))
        };
        let feeds = [source("feed", SourceKind::Prose)];
        let mut states = IndexMap::new();
        let mut poll = |time: &str| {
            poll_sources(&mut states, &PollOptions { sources: Some(&feeds), ..PollOptions::new(&fetch, at(time)) });
        };
        poll("2026-10-21T10:00:00Z");
        poll("2026-10-21T10:10:00Z");
        poll("2026-10-21T10:20:00Z");
        // The failed poll is due again immediately, inside the interval.
        poll("2026-10-21T10:20:30Z");
        let seen = seen.lock().expect("lock");
        assert!(!seen[0].iter().any(|(k, _)| k == "If-None-Match"));
        assert!(seen[1].contains(&("If-None-Match".to_string(), "\"v1\"".to_string())));
        assert_eq!(seen.len(), 4);
        assert_eq!(states["feed"].error, None);
        assert_eq!(states["feed"].status, Some(200));
    }

    #[test]
    fn http_error_is_recorded_on_the_feed() {
        let fetch = |_: Request| Ok(Response { status: 503, headers: Vec::new(), body: Vec::new() });
        let feeds = [source("feed", SourceKind::Prose)];
        let mut states = IndexMap::new();
        poll_sources(&mut states, &PollOptions { sources: Some(&feeds), ..PollOptions::new(&fetch, at("2026-10-21T10:00:00Z")) });
        assert_eq!(states["feed"].error.as_deref(), Some("HTTP 503"));
        assert_eq!(states["feed"].status, Some(503));
        assert_eq!(states["feed"].baselined, None);
    }

    #[test]
    fn osv_head_reports_the_baseline_then_only_a_newer_cursor() {
        let head = Mutex::new("2026-10-20T00:00:00Z,GHSA-1\n".to_string());
        let fetch = |req: Request| {
            assert!(req.headers.contains(&("Range".to_string(), "bytes=0-1023".to_string())));
            Ok(ok(&head.lock().expect("lock")))
        };
        let feeds = [SourceDef { ecosystem: Some("npm".into()), ..source("osv:npm", SourceKind::OsvHead) }];
        let mut states = IndexMap::new();
        let poll = |time: &str, states: &mut IndexMap<String, FeedState>| {
            poll_sources(states, &PollOptions { sources: Some(&feeds), ..PollOptions::new(&fetch, at(time)) })
        };
        assert_eq!(poll("2026-10-21T10:00:00Z", &mut states).osv_changed, ["npm"], "the first poll queries once");
        assert!(poll("2026-10-21T10:10:00Z", &mut states).osv_changed.is_empty());
        *head.lock().expect("lock") = "2026-10-21T09:00:00Z,GHSA-2\n".to_string();
        let changed = poll("2026-10-21T10:20:00Z", &mut states);
        assert_eq!(changed.osv_changed, ["npm"]);
        assert_eq!(states["osv:npm"].cursor.as_deref(), Some("2026-10-21T09:00:00Z"));
        *head.lock().expect("lock") = "not a csv".to_string();
        poll("2026-10-21T10:30:00Z", &mut states);
        assert_eq!(states["osv:npm"].error.as_deref(), Some("unexpected modified_id.csv"));
    }

    #[test]
    fn seen_keeps_the_newest_ids_in_js_key_order() {
        let keys = ["z", "20", "3", "a", "007", "100"].map(String::from);
        assert_eq!(js_key_order(keys.into_iter()), ["3", "20", "100", "z", "a", "007"]);
    }

    /// `deltaLog.json`: runs newest first, each `(fetchTime, new ids, updated ids)`, pretty-printed as the repository does.
    fn delta_log(runs: &[(&str, &[&str], &[&str])]) -> String {
        let refs = |ids: &[&str]| {
            let list: Vec<serde_json::Value> = ids.iter().map(|id| serde_json::json!({ "cveId": id, "dateUpdated": "2026-10-22T10:00:00.000Z" })).collect();
            serde_json::Value::Array(list)
        };
        let runs: Vec<serde_json::Value> = runs
            .iter()
            .map(|(time, new, updated)| serde_json::json!({ "fetchTime": time, "numberOfChanges": new.len() + updated.len(), "new": refs(new), "updated": refs(updated), "error": [] }))
            .collect();
        serde_json::to_string_pretty(&runs).expect("serializes")
    }

    #[test]
    fn parse_delta_head_keeps_the_complete_runs_and_the_time_of_the_one_a_range_cut() {
        let log = delta_log(&[
            ("2026-10-22T20:21:28.182Z", &["CVE-2026-115419"], &["CVE-2024-3727"]),
            ("2026-10-22T19:56:13.390Z", &[], &["CVE-2024-11831", "CVE-2024-9355"]),
        ]);
        let cut_at = log.find("CVE-2024-9355").expect("an id of the second run") + 4;
        let (runs, cut) = parse_delta_head(&log[..cut_at]);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].fetch_time, "2026-10-22T20:21:28.182Z");
        assert_eq!((runs[0].new[0].cve_id.as_str(), runs[0].updated[0].cve_id.as_str()), ("CVE-2026-115419", "CVE-2024-3727"));
        assert_eq!(cut.as_deref(), Some("2026-10-22T19:56:13.390Z"));
        let (all, none) = parse_delta_head(&log);
        assert_eq!((all.len(), none), (2, None));
    }

    #[test]
    fn cve_list_reads_the_log_conditionally_and_fetches_only_the_records_of_newer_runs() {
        let log = Mutex::new(delta_log(&[("2026-10-22T10:00:00.000Z", &[], &["CVE-2026-1000"])]));
        type Seen = (String, Vec<(String, String)>);
        let requests: Mutex<Vec<Seen>> = Mutex::new(Vec::new());
        let down = std::sync::atomic::AtomicBool::new(false);
        let fetch = |req: Request| {
            requests.lock().expect("lock").push((req.url.clone(), req.headers.clone()));
            if req.url.ends_with("/cves/deltaLog.json") {
                let body = log.lock().expect("lock").clone();
                let etag = format!("\"{}\"", body.len());
                if req.headers.contains(&("If-None-Match".to_string(), etag.clone())) {
                    return Ok(Response { status: 304, headers: Vec::new(), body: Vec::new() });
                }
                let range = format!("bytes 0-{}/{}", body.len() - 1, body.len());
                return Ok(Response { status: 206, headers: vec![("etag".into(), etag), ("content-range".into(), range)], body: body.into_bytes() });
            }
            if down.load(std::sync::atomic::Ordering::SeqCst) {
                return Ok(Response { status: 503, headers: Vec::new(), body: Vec::new() });
            }
            let id = req.url.rsplit('/').next().and_then(|f| f.strip_suffix(".json")).expect("a record file").to_string();
            Ok(ok(&serde_json::json!({ "cveMetadata": { "cveId": id, "state": "PUBLISHED" }, "containers": { "cna": {} } }).to_string()))
        };
        let feeds = [SourceDef::new("cve-list", "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json", SourceKind::CveList)];
        let mut states = IndexMap::new();
        let poll = |minutes: u32, states: &mut IndexMap<String, FeedState>| {
            let time = at("2026-10-22T10:00:00Z") + Duration::from_secs(u64::from(minutes) * 60);
            poll_sources(states, &PollOptions { sources: Some(&feeds), ..PollOptions::new(&fetch, time) })
        };
        let ids = |polled: &PollResult| polled.cve_records.iter().map(|r| r.id.clone()).collect::<Vec<_>>();

        // The first read is history: it records where the log stands and fetches no record.
        assert!(poll(0, &mut states).cve_records.is_empty());
        {
            let seen = requests.lock().expect("lock");
            assert_eq!(seen.len(), 1);
            assert!(seen[0].1.contains(&("Range".to_string(), "bytes=0-65535".to_string())));
        }
        // Nothing changed: the conditional request answers 304.
        assert!(poll(10, &mut states).cve_records.is_empty());
        assert!(requests.lock().expect("lock")[1].1.iter().any(|(k, _)| k == "If-None-Match"));
        // Two newer runs: the new CVE first, then the update; the records come from their own files.
        *log.lock().expect("lock") = delta_log(&[
            ("2026-10-22T10:25:00.000Z", &[], &["CVE-2026-2000"]),
            ("2026-10-22T10:15:00.000Z", &["CVE-2026-2000"], &["CVE-2026-1000"]),
            ("2026-10-22T10:00:00.000Z", &[], &["CVE-2026-1000"]),
        ]);
        let third = poll(20, &mut states);
        assert_eq!(ids(&third), ["CVE-2026-2000", "CVE-2026-1000"]);
        let urls: Vec<String> = requests.lock().expect("lock").iter().map(|(url, _)| url.clone()).collect();
        assert!(urls.contains(&"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/2xxx/CVE-2026-2000.json".to_string()));
        assert_eq!(states["cve-list"].cursor.as_deref(), Some("2026-10-22T10:25:00.000Z"));
        assert_eq!(states["cve-list"].fresh, Some(2));
        // A record that cannot be fetched is kept and retried, even while the log itself answers 304.
        down.store(true, std::sync::atomic::Ordering::SeqCst);
        *log.lock().expect("lock") = delta_log(&[("2026-10-22T10:40:00.000Z", &["CVE-2026-3000"], &[])]);
        assert!(poll(30, &mut states).cve_records.is_empty());
        assert_eq!(states["cve-list"].error, None);
        assert_eq!(states["cve-list"].pending, Some(vec![PendingRecord { id: "CVE-2026-3000".into(), new: true, tries: 1 }]));
        down.store(false, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(ids(&poll(40, &mut states)), ["CVE-2026-3000"]);
        assert_eq!(states["cve-list"].pending, None);
        assert_eq!(states["cve-list"].status, Some(304));
    }
}
