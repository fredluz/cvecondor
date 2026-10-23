// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! The CVE List (CVEProject/cvelistV5): a CVE JSON 5 record, read for what the watcher needs (the CNA's
//! `affected` entries, CISA's ADP container for severity and exploitation), and matched against the inventory.
//!
//! A record is matched by product, never by its description: a WordPress plugin's CVE says "WordPress" in its text
//! and is not about WordPress. An entry whose product *is* something we run (exactly, or with an edition word:
//! `NGINX Open Source`) is read against the item's version. A range that settles it opens a case; an entry that
//! names the product but gives no range we can read (free text, git or rpm versions, nothing) goes to the
//! name-match + classifier path as a candidate.

use anyhow::{Context, Result, bail};
use indexmap::IndexMap;
use serde_json::Value;

use crate::feeds::ProseItem;
use crate::matching::{Severity, bucket, carrier_terms, label, product_terms};
use crate::types::{Inventory, InventoryItem, ItemKind};
use crate::versions::{compare_loose, satisfies};

/// The feed id: `disabledSources`, `FeedState`, a case's `sources`.
pub const SOURCE: &str = "cve-list";

/// One `versions[]` entry of an `affected` entry.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VersionRange {
    pub version: String,
    /// `affected`, `unaffected` or `unknown`.
    pub status: String,
    pub less_than: Option<String>,
    pub less_than_or_equal: Option<String>,
    pub version_type: Option<String>,
    /// The `at` of each `changes[]` step that turns the range unaffected: a release that fixes it.
    pub fixed_at: Vec<String>,
}

/// One `affected[]` entry.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AffectedEntry {
    pub vendor: String,
    pub product: String,
    pub package_name: Option<String>,
    pub collection_url: Option<String>,
    /// `affected`, `unaffected` or `unknown`: what the CNA says of every version it did not list.
    pub default_status: String,
    pub versions: Vec<VersionRange>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CveRecord {
    pub id: String,
    /// `PUBLISHED`; a `REJECTED` record is read and ignored.
    pub published: bool,
    pub updated: String,
    pub title: String,
    pub description: String,
    /// The CNA's entries; CISA's ADP entries only when the CNA gave no version at all.
    pub affected: Vec<AffectedEntry>,
    /// The highest CVSS 3.x/4.0 bucket of the CNA's and CISA's metrics.
    pub severity: Severity,
    /// CISA's SSVC says `Exploitation: active`, or its ADP container carries a KEV entry.
    pub exploited: bool,
    pub references: Vec<String>,
}

pub fn cve_org_url(id: &str) -> String {
    format!("https://www.cve.org/CVERecord?id={id}")
}

fn text(v: &Value) -> Option<String> {
    v.as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

fn entries(container: &Value) -> Vec<AffectedEntry> {
    container["affected"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|a| AffectedEntry {
            vendor: text(&a["vendor"]).unwrap_or_default(),
            product: text(&a["product"]).unwrap_or_default(),
            package_name: text(&a["packageName"]),
            collection_url: text(&a["collectionURL"]),
            default_status: text(&a["defaultStatus"]).unwrap_or_default().to_lowercase(),
            versions: a["versions"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|v| VersionRange {
                    version: text(&v["version"]).unwrap_or_default(),
                    status: text(&v["status"]).unwrap_or_default().to_lowercase(),
                    less_than: text(&v["lessThan"]),
                    less_than_or_equal: text(&v["lessThanOrEqual"]),
                    version_type: text(&v["versionType"]),
                    fixed_at: v["changes"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter(|c| c["status"].as_str() == Some("unaffected"))
                        .filter_map(|c| text(&c["at"]))
                        .collect(),
                })
                .collect(),
        })
        .collect()
}

/// The highest severity of a container's CVSS metrics, and whether its other metrics say the CVE is exploited.
fn metrics(container: &Value) -> (Severity, bool) {
    let mut severity = Severity::Unknown;
    let mut exploited = false;
    for metric in container["metrics"].as_array().into_iter().flatten() {
        for key in ["cvssV4_0", "cvssV3_1", "cvssV3_0"] {
            let Some(cvss) = metric.get(key) else { continue };
            let found = match cvss["baseScore"].as_f64() {
                Some(score) => bucket(score),
                None => label(cvss["baseSeverity"].as_str()),
            };
            if found.rank() > severity.rank() {
                severity = found;
            }
        }
        let other = &metric["other"];
        match other["type"].as_str() {
            Some("kev") => exploited = true,
            Some("ssvc") => {
                let options = other["content"]["options"].as_array().into_iter().flatten();
                exploited |= options.filter_map(|o| o["Exploitation"].as_str()).any(|e| e.eq_ignore_ascii_case("active"));
            }
            _ => {}
        }
    }
    (severity, exploited)
}

pub fn parse_record(json: &str) -> Result<CveRecord> {
    let v: Value = serde_json::from_str(json).context("invalid CVE record JSON")?;
    let Some(id) = text(&v["cveMetadata"]["cveId"]) else { bail!("CVE record without a cveId") };
    let cna = &v["containers"]["cna"];
    let adp: Vec<&Value> =
        v["containers"]["adp"].as_array().into_iter().flatten().filter(|c| c["providerMetadata"]["shortName"].as_str() == Some("CISA-ADP")).collect();
    let mut affected = entries(cna);
    if !affected.iter().any(|a| !a.versions.is_empty()) {
        affected.extend(adp.iter().flat_map(|c| entries(c)));
    }
    let (mut severity, mut exploited) = metrics(cna);
    for container in &adp {
        let (s, e) = metrics(container);
        if s.rank() > severity.rank() {
            severity = s;
        }
        exploited |= e;
    }
    let descriptions: Vec<&Value> = cna["descriptions"].as_array().into_iter().flatten().collect();
    let english = descriptions.iter().find(|d| d["lang"].as_str().is_some_and(|l| l.starts_with("en"))).or(descriptions.first());
    Ok(CveRecord {
        published: v["cveMetadata"]["state"].as_str() == Some("PUBLISHED"),
        updated: text(&v["cveMetadata"]["dateUpdated"]).unwrap_or_default(),
        title: text(&cna["title"]).unwrap_or_default(),
        description: english.and_then(|d| text(&d["value"])).unwrap_or_default(),
        affected,
        severity,
        exploited,
        references: cna["references"].as_array().into_iter().flatten().filter_map(|r| text(&r["url"])).take(3).collect(),
        id,
    })
}

// ---------- versions ----------

/// `versionType`s whose versions this crate can order. `git` (commits), `rpm`, `deb`, `apk` and the rest cannot be.
fn orderable(version_type: Option<&str>) -> bool {
    matches!(
        version_type.map(str::to_lowercase).as_deref(),
        None | Some("" | "semver" | "custom" | "python" | "maven" | "ecosystem" | "npm" | "gem" | "go" | "cargo")
    )
}

fn numeric(version: &str) -> bool {
    version.trim_start_matches(['v', 'V']).starts_with(|c: char| c.is_ascii_digit())
}

/// `1.27` and `1.27.3` share a branch.
fn same_branch(a: &str, b: &str) -> bool {
    let head = |v: &str| v.trim_start_matches(['v', 'V']).split('.').take(2).map(str::to_string).collect::<Vec<_>>();
    head(a) == head(b)
}

/// Whether `version` is in the range one `versions[]` entry names; `None` when the entry cannot be read.
fn in_range(r: &VersionRange, version: &str) -> Option<bool> {
    if !orderable(r.version_type.as_deref()) || r.version.contains(':') {
        return None;
    }
    let low = r.version.as_str();
    let wild = low.contains('*') || low.contains(['x', 'X']);
    let upper = r.less_than.as_deref().map(|hi| (hi, false)).or_else(|| r.less_than_or_equal.as_deref().map(|hi| (hi, true)));
    let Some((high, inclusive)) = upper else {
        return match low {
            "*" => Some(true),
            _ if wild => satisfies(version, &low.replace(['*', 'X'], "x")).ok(),
            _ if numeric(low) => Some(compare_loose(version, low).is_eq()),
            _ => None,
        };
    };
    if high.contains(':') || (high != "*" && (high.contains('*') || !numeric(high))) {
        return None;
    }
    let open_below = matches!(low, "" | "0" | "*" | "0.0" | "0.0.0");
    let above = if open_below {
        true
    } else {
        let low = low.trim_end_matches(".*").trim_end_matches(".x");
        if !numeric(low) || low.contains('*') {
            return None;
        }
        compare_loose(version, low).is_ge()
    };
    let below = match high {
        "*" => true,
        _ if inclusive => compare_loose(version, high).is_le(),
        _ => compare_loose(version, high).is_lt(),
    };
    Some(above && below)
}

/// What one entry says about one version.
#[derive(Debug, Clone, PartialEq)]
pub enum Reading {
    /// Affected, and the releases the entry names that fix it.
    Affected(Vec<String>),
    Unaffected,
    /// The entry names the product but not a range this version can be read against.
    Undecided,
}

/// An `affected` entry's range read against `version`.
pub fn read_entry(entry: &AffectedEntry, version: &str) -> Reading {
    if entry.versions.is_empty() {
        return if entry.default_status == "unaffected" { Reading::Unaffected } else { Reading::Undecided };
    }
    let (mut affected, mut fixes): (bool, Vec<String>) = (false, Vec::new());
    let (mut unaffected, mut undecided) = (false, false);
    let push = |fixes: &mut Vec<String>, v: &str| {
        if numeric(v) && compare_loose(v, version).is_gt() && !fixes.iter().any(|f| f == v) {
            fixes.push(v.to_string());
        }
    };
    for r in &entry.versions {
        match r.status.as_str() {
            "affected" => match in_range(r, version) {
                Some(true) => {
                    // A `changes` step at or below the version, in its branch or past the newest fix, has fixed it.
                    let newest = r.fixed_at.iter().filter(|a| numeric(a)).max_by(|a, b| compare_loose(a, b));
                    let fixed = r
                        .fixed_at
                        .iter()
                        .filter(|at| numeric(at))
                        .any(|at| compare_loose(version, at).is_ge() && (same_branch(version, at) || newest.is_some_and(|n| compare_loose(at, n).is_eq())));
                    if fixed {
                        continue;
                    }
                    affected = true;
                    if let Some(hi) = r.less_than.as_deref() {
                        push(&mut fixes, hi);
                    }
                    for at in &r.fixed_at {
                        push(&mut fixes, at);
                    }
                }
                Some(false) => {}
                None => undecided = true,
            },
            "unaffected" => unaffected |= in_range(r, version) == Some(true),
            _ => {}
        }
    }
    if unaffected {
        Reading::Unaffected
    } else if affected {
        Reading::Affected(fixes)
    } else if undecided {
        Reading::Undecided
    } else if entry.default_status == "affected" {
        // Everything not listed is affected: the unaffected entries above the version are its fixes.
        for r in entry.versions.iter().filter(|r| r.status == "unaffected") {
            push(&mut fixes, &r.version);
        }
        Reading::Affected(fixes)
    } else {
        Reading::Unaffected
    }
}

/// The part of an item's version that is compared: a leading `1.2.3`, an epoch and a distro revision dropped; a
/// package keeps what its lockfile pinned. `None` for a tag like `latest`.
fn comparable(item: &InventoryItem) -> Option<String> {
    let version = item.version.trim();
    let version = version.trim_start_matches(['v', 'V']);
    if item.kind == ItemKind::Package {
        return numeric(version).then(|| version.to_string());
    }
    let version = match version.split_once(':') {
        Some((epoch, rest)) if epoch.bytes().all(|b| b.is_ascii_digit()) => rest,
        _ => version,
    };
    let end = version.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(version.len());
    let lead = version[..end].trim_end_matches('.');
    lead.starts_with(|c: char| c.is_ascii_digit()).then(|| lead.to_string())
}

// ---------- names ----------

/// Words an entry's product may add to a product we run without becoming another product.
const EDITION_WORDS: &[&str] = &["open", "source", "oss", "community", "edition", "ce", "server", "(oss)"];

fn squash(text: &str) -> String {
    text.to_lowercase().split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The entry's product is the term, with at most an edition word: `NGINX Open Source` is `nginx`, `NGINX Plus` is not.
fn is_product(product: &str, term: &str) -> bool {
    let (product, term) = (squash(product), squash(term));
    match product.strip_prefix(term.as_str()) {
        Some("") => true,
        Some(rest) => rest.strip_prefix(' ').is_some_and(|rest| rest.split_whitespace().all(|w| EDITION_WORDS.contains(&w))),
        None => false,
    }
}

/// The package registry a `collectionURL` names, in the inventory's ecosystem spelling.
fn registry(url: &str) -> Option<&'static str> {
    let url = url.to_lowercase();
    [("npmjs.", "npm"), ("pypi.org", "PyPI"), ("packagist.org", "Packagist"), ("crates.io", "crates.io"), ("rubygems.org", "RubyGems"), ("pkg.go.dev", "Go")]
        .into_iter()
        .find(|(host, _)| url.contains(host))
        .map(|(_, ecosystem)| ecosystem)
}

fn package_key(ecosystem: &str, name: &str) -> String {
    let name = name.to_lowercase();
    if ecosystem == "PyPI" { name.replace(['_', '.'], "-") } else { name }
}

/// Whether the entry names this lockfile package: by `packageName` on its registry, or, with none, by product.
fn is_package(entry: &AffectedEntry, item: &InventoryItem) -> bool {
    let Some(ecosystem) = item.ecosystem.as_deref() else { return false };
    let registry = entry.collection_url.as_deref().and_then(registry);
    match entry.package_name.as_deref() {
        Some(name) => registry == Some(ecosystem) && package_key(ecosystem, name) == package_key(ecosystem, &item.name),
        None => {
            (registry.is_none() || registry == Some(ecosystem))
                && !entry.product.is_empty()
                && package_key(ecosystem, &entry.product) == package_key(ecosystem, &item.name)
        }
    }
}

/// What a record says about the inventory.
#[derive(Debug, Clone, Default)]
pub struct Matched {
    /// Items a readable range puts in the affected versions, each with the releases that fix it.
    pub affected: Vec<(InventoryItem, Vec<String>)>,
    /// Items of a product the record names where no range settles it, and items that carry the library it names
    /// built in: the name-match + classifier path, or riders on the case the affected items open.
    pub candidates: Vec<InventoryItem>,
    /// The inventory's words for the products matched.
    pub terms: Vec<String>,
}

fn same_item(a: &InventoryItem, b: &InventoryItem) -> bool {
    a.host == b.host && a.r#where == b.r#where && a.kind == b.kind && a.name == b.name && a.version == b.version && a.path == b.path
}

pub fn match_record(record: &CveRecord, inventory: &Inventory) -> Matched {
    let mut words = product_terms(inventory);
    for item in inventory.items.iter().filter(|i| matches!(i.kind, ItemKind::Runtime | ItemKind::Image | ItemKind::OsPackage)) {
        let list = words.entry(item.name.to_lowercase()).or_default();
        if !list.iter().any(|i| std::ptr::eq(*i, item)) {
            list.push(item);
        }
    }
    let carriers = carrier_terms(inventory);
    let mut matched = Matched::default();
    let mut verdicts: Vec<(&InventoryItem, Reading)> = Vec::new();
    let mut terms: IndexMap<String, ()> = IndexMap::new();
    for entry in &record.affected {
        let mut touched: Vec<(&InventoryItem, Option<&str>)> = Vec::new();
        for (term, items) in &words {
            if !entry.product.is_empty() && is_product(&entry.product, term) {
                touched.extend(
                    items.iter().filter(|i| matches!(i.kind, ItemKind::Runtime | ItemKind::Image | ItemKind::OsPackage)).map(|i| (*i, Some(term.as_str()))),
                );
            }
        }
        touched.extend(inventory.items.iter().filter(|i| i.kind == ItemKind::Package && is_package(entry, i)).map(|i| (i, None)));
        for (item, term) in touched {
            if let Some(term) = term {
                terms.insert(term.to_string(), ());
            }
            let reading = comparable(item).map_or(Reading::Undecided, |v| read_entry(entry, &v));
            verdicts.push((item, reading));
        }
        // What carries the library built in has its own versions: the library's range never settles it.
        for (library, items) in &carriers {
            if !entry.product.is_empty() && is_product(&entry.product, library) {
                terms.insert(library.clone(), ());
                verdicts.extend(items.iter().map(|i| (*i, Reading::Undecided)));
            }
        }
    }
    for (item, reading) in verdicts {
        match reading {
            // A distro's package carries its own backported fixes: the upstream range only says it is worth a look.
            Reading::Affected(_) | Reading::Undecided if item.kind == ItemKind::OsPackage => {
                if !matched.candidates.iter().any(|c| same_item(c, item)) {
                    matched.candidates.push(item.clone());
                }
            }
            Reading::Affected(fixes) => match matched.affected.iter_mut().find(|(i, _)| same_item(i, item)) {
                Some((_, known)) => {
                    for f in fixes {
                        if !known.contains(&f) {
                            known.push(f);
                        }
                    }
                }
                None => matched.affected.push((item.clone(), fixes)),
            },
            Reading::Undecided => {
                if !matched.candidates.iter().any(|c| same_item(c, item)) {
                    matched.candidates.push(item.clone());
                }
            }
            Reading::Unaffected => {}
        }
    }
    matched.candidates.retain(|c| !matched.affected.iter().any(|(a, _)| same_item(a, c)));
    matched.terms = terms.into_keys().collect();
    matched
}

fn range_text(r: &VersionRange) -> String {
    let bound = match (&r.less_than, &r.less_than_or_equal) {
        (Some(hi), _) => format!(" before {hi}"),
        (None, Some(hi)) => format!(" through {hi}"),
        _ => String::new(),
    };
    format!("{} {}{bound}", r.status, r.version)
}

/// The record as a prose item, for the classifier: the CNA's own words, and what it says about versions.
pub fn prose_item(record: &CveRecord) -> ProseItem {
    let affected: Vec<String> = record
        .affected
        .iter()
        .take(6)
        .map(|a| {
            let versions = if a.versions.is_empty() {
                format!("no versions given (default {})", if a.default_status.is_empty() { "unknown" } else { &a.default_status })
            } else {
                a.versions.iter().take(6).map(range_text).collect::<Vec<_>>().join(", ")
            };
            format!("{} {}: {versions}", a.vendor, a.product).trim().to_string()
        })
        .collect();
    let title = if record.title.is_empty() { record.id.clone() } else { format!("{}: {}", record.id, record.title) };
    ProseItem {
        source: SOURCE.to_string(),
        id: record.id.clone(),
        title,
        text: format!("{}\nAffected, per the CNA: {}", record.description, affected.join("; ")),
        url: cve_org_url(&record.id),
        published: Some(record.updated.clone()).filter(|u| !u.is_empty()),
        cves: vec![record.id.clone()],
        exploited: record.exploited.then_some(true),
        high_signal: record.exploited,
        changed: None,
        vendor: None,
        news: None,
    }
}

/// The case title for a record: the CNA's title, else the start of its description.
pub fn headline(record: &CveRecord) -> Option<String> {
    let line = if record.title.is_empty() { record.description.lines().next().unwrap_or("") } else { record.title.as_str() };
    let line: String = line.chars().take(140).collect();
    Some(line).filter(|l| !l.is_empty())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn inventory() -> Inventory {
        serde_json::from_value(json!({
            "collectedAt": "2026-10-21T06:00:00.000Z",
            "items": [
                { "host": "web1", "where": "container:blog", "kind": "runtime", "name": "php", "version": "8.3.28", "running": true },
                { "host": "web1", "where": "container:old-shop", "kind": "runtime", "name": "php", "version": "8.2.20", "running": false },
                { "host": "web1", "where": "host", "kind": "runtime", "name": "nginx", "version": "1.27.0" },
                { "host": "web1", "where": "host", "kind": "os-package", "ecosystem": "Debian:12", "name": "nginx", "version": "1.22.1-9" },
                { "host": "github", "where": "repo:acme/api", "kind": "package", "ecosystem": "npm", "name": "left-pad", "version": "1.0.0" },
                { "host": "github", "where": "repo:acme/blog", "kind": "image", "name": "wordpress", "version": "6.8.3-php8.3-apache" }
            ]
        }))
        .expect("the inventory parses")
    }

    fn record(cna: serde_json::Value, adp: serde_json::Value) -> CveRecord {
        let record = json!({
            "cveMetadata": { "cveId": "CVE-2026-100001", "state": "PUBLISHED", "dateUpdated": "2026-10-22T20:08:10.489Z" },
            "containers": { "cna": cna, "adp": adp }
        });
        parse_record(&record.to_string()).expect("the record parses")
    }

    /// The PHP RCE of Oct 2026 as the CVE List holds it: wildcard branches with a `lessThan` each.
    fn php() -> CveRecord {
        record(
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
            }),
            json!([]),
        )
    }

    #[test]
    fn semver_ranges_match_exactly_and_name_the_releases_that_fix_them() {
        let php = php();
        assert_eq!(php.severity, Severity::Critical);
        let matched = match_record(&php, &inventory());
        let found: Vec<(String, &str, Vec<String>)> =
            matched.affected.iter().map(|(i, fixes)| (i.r#where.clone(), i.version.as_str(), fixes.clone())).collect();
        assert_eq!(
            found,
            [("container:blog".to_string(), "8.3.28", vec!["8.3.36".to_string()]), ("container:old-shop".to_string(), "8.2.20", vec!["8.2.35".to_string()])]
        );
        assert!(matched.candidates.is_empty(), "a readable range settles it either way");
        // Past the fix in its branch, and in a branch the record does not list: not affected.
        let at_fix = Inventory { items: vec![inventory().items[0].clone()], ..inventory() };
        let patched = |version: &str| {
            let mut inv = at_fix.clone();
            inv.items[0].version = version.to_string();
            let m = match_record(&php, &inv);
            (m.affected.len(), m.candidates.len())
        };
        assert_eq!([patched("8.3.36"), patched("8.3.40"), patched("8.1.30"), patched("8.4.26")], [(0, 0), (0, 0), (0, 0), (1, 0)]);
    }

    #[test]
    fn a_fix_in_each_branch_leaves_the_versions_between_branches_affected() {
        // CVE-2024-7347's shape: one open range from 1.5.13, unaffected `changes` at 1.26.2 and 1.27.1; NGINX Plus is another product.
        let nginx = record(
            json!({
                "affected": [
                    { "vendor": "F5", "product": "NGINX Open Source", "defaultStatus": "unknown", "versions": [
                        { "status": "affected", "version": "1.5.13", "lessThan": "*", "versionType": "semver",
                          "changes": [{ "at": "1.26.2", "status": "unaffected" }, { "at": "1.27.1", "status": "unaffected" }] }
                    ] },
                    { "vendor": "F5", "product": "NGINX Plus", "defaultStatus": "unknown", "versions": [
                        { "status": "affected", "version": "R4", "lessThan": "*", "versionType": "custom", "changes": [{ "at": "R32 P1", "status": "unaffected" }] }
                    ] }
                ]
            }),
            json!([]),
        );
        let entry = &nginx.affected[0];
        let read = |v: &str| read_entry(entry, v);
        assert_eq!(read("1.27.0"), Reading::Affected(vec!["1.27.1".to_string()]));
        assert_eq!(read("1.25.5"), Reading::Affected(vec!["1.26.2".to_string(), "1.27.1".to_string()]));
        assert_eq!([read("1.26.3"), read("1.27.1"), read("1.28.0")], [Reading::Unaffected, Reading::Unaffected, Reading::Unaffected]);
        assert_eq!(read("1.4.0"), Reading::Unaffected);
        let matched = match_record(&nginx, &inventory());
        let direct: Vec<&str> = matched.affected.iter().map(|(i, _)| i.version.as_str()).collect();
        assert_eq!(direct, ["1.27.0"], "the binary is read against the range");
        // Debian's 1.22.1-9 carries its own backported fixes: the upstream range only makes it worth a look.
        assert_eq!(matched.candidates.iter().map(|i| i.version.as_str()).collect::<Vec<_>>(), ["1.22.1-9"]);
    }

    #[test]
    fn product_and_version_strings_without_a_readable_range_are_candidates_never_exact_hits() {
        let strings = record(
            json!({
                "affected": [
                    { "vendor": "WordPress", "product": "WordPress", "versions": [{ "status": "affected", "version": "before 6.8.4" }] },
                    { "vendor": "Acme", "product": "Acme Slider - WordPress Plugin", "versions": [{ "status": "affected", "version": "1.0", "lessThanOrEqual": "2.1" }] },
                    { "vendor": "Red Hat", "product": "Some Product", "packageName": "left-pad", "collectionURL": "https://access.redhat.com/downloads/content/package-browser/", "defaultStatus": "affected" },
                    { "vendor": "Linux", "product": "Linux", "versions": [{ "status": "affected", "version": "5.10", "versionType": "git", "lessThan": "abc123" }] }
                ]
            }),
            json!([]),
        );
        let matched = match_record(&strings, &inventory());
        assert!(matched.affected.is_empty());
        assert_eq!(
            matched.candidates.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(),
            ["wordpress"],
            "a plugin 'for WordPress' and a Red Hat package of the same name are not those products"
        );
        // The same package on its registry, with a range, is read exactly.
        let npm = record(
            json!({ "affected": [{ "vendor": "left-pad", "product": "left-pad", "packageName": "left-pad", "collectionURL": "https://www.npmjs.com", "versions": [{ "status": "affected", "version": "0", "lessThan": "1.3.1", "versionType": "semver" }] }] }),
            json!([]),
        );
        assert_eq!(match_record(&npm, &inventory()).affected[0].1, ["1.3.1"]);
    }

    #[test]
    fn cisa_adp_adds_severity_exploitation_and_the_affected_the_cna_left_out() {
        let thin = record(
            json!({ "title": "Widget flaw", "descriptions": [{ "lang": "en", "value": "A flaw." }], "affected": [{ "vendor": "Acme", "product": "Widget", "defaultStatus": "unknown" }] }),
            json!([
                { "providerMetadata": { "shortName": "CVE" }, "references": [] },
                {
                    "providerMetadata": { "shortName": "CISA-ADP" },
                    "affected": [{ "vendor": "nginx", "product": "nginx", "versions": [{ "status": "affected", "version": "1.20.0", "lessThanOrEqual": "1.27.0", "versionType": "semver" }] }],
                    "metrics": [
                        { "cvssV3_1": { "version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL" } },
                        { "other": { "type": "ssvc", "content": { "options": [{ "Exploitation": "active" }, { "Automatable": "yes" }] } } }
                    ]
                }
            ]),
        );
        assert_eq!((thin.severity, thin.exploited), (Severity::Critical, true));
        assert_eq!(thin.affected.iter().map(|a| a.product.as_str()).collect::<Vec<_>>(), ["Widget", "nginx"]);
        let matched = match_record(&thin, &inventory());
        assert_eq!(matched.affected.iter().map(|(i, _)| i.version.as_str()).collect::<Vec<_>>(), ["1.27.0"]);
        // "Exploitation: none" is not exploitation.
        let quiet = record(
            json!({}),
            json!([{ "providerMetadata": { "shortName": "CISA-ADP" }, "metrics": [{ "other": { "type": "ssvc", "content": { "options": [{ "Exploitation": "none" }] } } }] }]),
        );
        assert!(!quiet.exploited);
    }
}
