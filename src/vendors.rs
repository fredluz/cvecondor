// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! The user's vendors: detected from what the inventory shows (env var names,
//! config files, SDK packages, images, deployment records, service domains)
//! plus the ones named in the config. Only these are watched; the catalogue is
//! wide so detection is. A vendor incident (a hosting platform breach) has no
//! CVE: what matters is which of the user's keys belong to or passed through it.

pub mod catalog;

use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::feeds::{ProseItem, SourceDef, SourceKind};
use crate::matching::mentions;
use crate::secrets::{SecretFinding, names_a_secret};
use crate::types::{Inventory, ItemKind, VendorSignalKind};
use crate::vendors::catalog::{VENDORS, VendorDef, VendorFeed, package_vendor, vendors_for_file};
use crate::watch::Place;

#[derive(Debug, Clone, PartialEq)]
pub struct UserVendor {
    pub id: String,
    pub name: String,
    pub aliases: Vec<String>,
    pub feeds: Vec<VendorFeed>,
    /// Why we think the user uses it: `github repo:acme/api vercel.json`.
    pub evidence: Vec<String>,
    pub places: Vec<Place>,
    /// A place deploys on it (a config file or deployment record): that place's env lives there too.
    pub hosting: Vec<Place>,
    pub manual: bool,
}

/// One place a key is stored: `vercel:acme-web (production)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationPlace {
    pub place: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
}

/// `{ "KEY_NAME": [{ "place": "vercel:acme-web (production)", "vendor": "vercel" }] }`, written at install.
pub type RotationMap = IndexMap<String, Vec<RotationPlace>>;

#[derive(Debug, Clone)]
pub struct VendorCandidate {
    pub vendor: UserVendor,
    pub items: Vec<ProseItem>,
}

pub const VENDOR_LABELS: &[&str] = &["security-incident", "not-security", "unsure"];

/// Env var names: exact, or prefixes ending in `_`.
fn env_match(patterns: &[String], name: &str) -> bool {
    patterns.iter().any(|p| if p.ends_with('_') { name.starts_with(p.as_str()) } else { name == p })
}

fn domain_match(suffixes: &[String], host: &str) -> bool {
    suffixes.iter().any(|s| host == s || host.strip_suffix(s.as_str()).is_some_and(|rest| rest.ends_with('.')))
}

/// `ghcr.io/acme/api:1.2@sha256:…` → `api`.
fn last_segment(reference: &str) -> &str {
    let end = reference.find([':', '@']).unwrap_or(reference.len());
    reference[..end].rsplit('/').next().unwrap_or(reference)
}

/// JS `slice(0, n)`: the first `n` UTF-16 code units (whole characters: a pair is never split).
fn js_slice(text: &str, n: usize) -> &str {
    let mut units = 0;
    for (at, c) in text.char_indices() {
        units += c.len_utf16();
        if units > n {
            return &text[..at];
        }
    }
    text
}

/// First occurrences only, in order.
fn dedup(items: impl IntoIterator<Item = String>) -> Vec<String> {
    items.into_iter().collect::<IndexSet<_>>().into_iter().collect()
}

fn where_of(host: &str, place: &str) -> String {
    format!("{host} {place}")
}

/// The vendors this user depends on: what the inventory shows, plus the ones named in the config
/// (`ignoreVendors` removed). Sorted by id.
pub fn detect_vendors(inventory: &Inventory, config: &Config) -> Vec<UserVendor> {
    let mut found: IndexMap<String, UserVendor> = IndexMap::new();
    let mut note = |def: &VendorDef, place: Place, why: &str, hosting: bool| {
        if config.ignore_vendors.contains(&def.id) {
            return;
        }
        let v = found.entry(def.id.clone()).or_insert_with(|| UserVendor {
            id: def.id.clone(),
            name: def.name.clone(),
            aliases: dedup(def.aliases.iter().cloned()),
            feeds: def.feeds.clone(),
            evidence: Vec::new(),
            places: Vec::new(),
            hosting: Vec::new(),
            manual: false,
        });
        let evidence = format!("{} {} {why}", place.host, place.r#where);
        if v.evidence.len() < 12 && !v.evidence.contains(&evidence) {
            v.evidence.push(evidence);
        }
        if !v.places.contains(&place) {
            v.places.push(place.clone());
        }
        if hosting && !v.hosting.contains(&place) {
            v.hosting.push(place);
        }
    };
    for s in &inventory.signals {
        let place = Place { host: s.host.clone(), r#where: s.r#where.clone() };
        match s.kind {
            VendorSignalKind::Env => {
                for def in VENDORS.iter().filter(|def| env_match(&def.env, &s.value)) {
                    note(def, place.clone(), &format!("env {}", s.value), false);
                }
            }
            VendorSignalKind::File => {
                for def in vendors_for_file(&s.value) {
                    note(def, place.clone(), &s.value, true);
                }
            }
            VendorSignalKind::Hostname => {
                for def in VENDORS.iter().filter(|def| domain_match(&def.hosts, &s.value)) {
                    note(def, place.clone(), &s.value, false);
                }
            }
            VendorSignalKind::Deployment => {
                let value = s.value.to_lowercase();
                for def in VENDORS.iter().filter(|def| def.deployers.iter().any(|d| value.contains(&d.to_lowercase()))) {
                    note(def, place.clone(), &format!("deployment {}", s.value), true);
                }
            }
        }
    }
    for secret in &inventory.secrets {
        let Some(name) = secret.name.as_deref().filter(|n| !n.is_empty()) else { continue };
        for def in VENDORS.iter().filter(|def| env_match(&def.env, name)) {
            note(def, Place { host: secret.host.clone(), r#where: secret.r#where.clone() }, &format!("{} {name}", secret.exposure.as_str()), false);
        }
    }
    for item in &inventory.items {
        let place = Place { host: item.host.clone(), r#where: item.r#where.clone() };
        match item.kind {
            ItemKind::Package => {
                if let Some(ecosystem) = item.ecosystem.as_deref().filter(|e| !e.is_empty()) {
                    for def in package_vendor(ecosystem, &item.name) {
                        note(def, place.clone(), &format!("{ecosystem} {}", item.name), false);
                    }
                }
            }
            ItemKind::Image => {
                for def in VENDORS.iter().filter(|def| def.images.iter().any(|i| last_segment(i) == item.name)) {
                    note(def, place.clone(), &format!("image {}", item.name), false);
                }
            }
            ItemKind::Platform => {
                if let Some(def) = VENDORS.iter().find(|v| v.id == item.name) {
                    note(def, place, &format!("deploys on {}", item.name), true);
                }
            }
            _ => {}
        }
    }
    for manual in &config.vendors {
        if config.ignore_vendors.contains(&manual.id) {
            continue;
        }
        let catalogue = VENDORS.iter().find(|v| v.id == manual.id);
        let v = found.entry(manual.id.clone()).or_insert_with(|| UserVendor {
            id: manual.id.clone(),
            name: manual.name.clone().or_else(|| catalogue.map(|c| c.name.clone())).unwrap_or_else(|| manual.id.clone()),
            aliases: catalogue.map(|c| c.aliases.clone()).unwrap_or_default(),
            feeds: catalogue.map(|c| c.feeds.clone()).unwrap_or_default(),
            evidence: Vec::new(),
            places: Vec::new(),
            hosting: Vec::new(),
            manual: true,
        });
        v.manual = true;
        let own = (catalogue.is_none() && manual.aliases.is_empty()).then(|| manual.name.as_deref().unwrap_or(&manual.id).to_lowercase());
        v.aliases = dedup(v.aliases.iter().cloned().chain(manual.aliases.iter().cloned()).chain(own));
        for feed in &manual.feeds {
            if !v.feeds.iter().any(|f| f.url == feed.url) {
                v.feeds.push(feed.clone());
            }
        }
        v.evidence.insert(0, "named in the config".to_string());
    }
    let mut out: Vec<UserVendor> = found.into_values().collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

/// One prose source per feed of each watched vendor.
pub fn vendor_sources(vendors: &[UserVendor]) -> Vec<SourceDef> {
    vendors
        .iter()
        .flat_map(|v| {
            v.feeds.iter().enumerate().map(|(i, feed)| {
                let suffix = if i > 0 { format!("-{i}") } else { String::new() };
                let mut source = SourceDef::new(format!("vendor:{}:{}{suffix}", v.id, feed.kind.as_str()), feed.url.as_str(), SourceKind::Prose);
                source.vendor = Some(v.id.clone());
                source.high_signal = Some(true);
                source.min_minutes = Some(10);
                source
            })
        })
        .collect()
}

/// Vendor-feed items belong to their vendor; news items count when their headline names a watched vendor. A vendor named
/// only further down is rarely the story's subject: "X compromised" whose summary says the attackers used stolen GitHub
/// tokens is X's incident, and the classifier, asked about GitHub, tends to call it GitHub's.
/// An item whose headline is a CVE is a product advisory, not an incident at the vendor (MSRC's feed lists every
/// Windows, .NET and kernel CVE): the CVE List and OSV sources match it by version against what the user runs.
pub fn vendor_candidates(items: &[ProseItem], vendors: &[UserVendor]) -> Vec<VendorCandidate> {
    let mut out: IndexMap<String, VendorCandidate> = IndexMap::new();
    for item in items.iter().filter(|i| !i.cves.iter().any(|id| i.title.contains(id.as_str()))) {
        let hits: Vec<&UserVendor> = if let Some(id) = item.vendor.as_deref().filter(|v| !v.is_empty()) {
            vendors.iter().filter(|v| v.id == id).collect()
        } else if item.news == Some(true) {
            vendors.iter().filter(|v| v.aliases.iter().any(|alias| mentions(&item.title, alias))).collect()
        } else {
            Vec::new()
        };
        for vendor in hits {
            let key = format!("{}\0{}\0{}", vendor.id, item.source, item.id);
            out.insert(key, VendorCandidate { vendor: vendor.clone(), items: vec![item.clone()] });
        }
    }
    out.into_values().collect()
}

pub fn vendor_instructions(vendor: &str) -> String {
    format!(
        "You read an incident or news item and decide whether it reports a security incident at {vendor} that could affect its customers.\n\
security-incident: a breach, unauthorized access, leaked or exposed customer credentials, tokens, keys or data, a compromised build or supply chain, malicious code in its packages, or a vulnerability in its hosted service that customers must act on (rotate, revoke, upgrade).\n\
not-security: a plain outage, degraded performance, elevated errors, maintenance, a feature or pricing announcement, a blog post, advice, tutorial, bug bounty or security program, researcher story or research write-up with no incident behind it, or an item that only mentions {vendor} in passing (another company's incident, a comparison).\n\
unsure: you cannot tell."
    )
}

pub fn vendor_input(c: &VendorCandidate) -> String {
    c.items.iter().map(|item| format!("[{}] {}\n{}", item.source, item.title, js_slice(&item.text, 2000))).collect::<Vec<_>>().join("\n\n")
}

/// What to rotate when a vendor is hit: keys that belong to it (by name, by
/// rule), the secrets of the places that deploy on it (their CI secrets, and
/// env vars whose name says secret: `VERSION` is no key), and what the
/// install-time rotation map says lives there. Names and places only.
pub fn rotation_for(vendor: &UserVendor, inventory: &Inventory, map: &RotationMap) -> Vec<String> {
    let env: &[String] = VENDORS.iter().find(|v| v.id == vendor.id).map(|d| d.env.as_slice()).unwrap_or(&[]);
    let mut lines: IndexSet<String> = IndexSet::new();
    let belongs = |s: &SecretFinding| {
        s.name.as_deref().is_some_and(|n| !n.is_empty() && env_match(env, n)) || s.providers.contains(&vendor.id) || s.kind.to_lowercase().contains(&vendor.id)
    };
    for s in inventory.secrets.iter().filter(|s| belongs(s)) {
        let fingerprint = s.fingerprint.as_deref().filter(|f| !f.is_empty()).map(|f| format!(" (fp {f})")).unwrap_or_default();
        lines.insert(format!(
            "{}{fingerprint}: belongs to {}; stored at {} {}",
            s.name.as_deref().unwrap_or(&s.kind),
            vendor.name,
            where_of(&s.host, &s.r#where),
            s.location
        ));
    }
    let hosted: IndexSet<String> = vendor.hosting.iter().map(|p| where_of(&p.host, &p.r#where)).collect();
    for s in inventory.signals.iter().filter(|s| s.kind == VendorSignalKind::Env && (s.path.as_deref() == Some("actions") || names_a_secret(&s.value))) {
        let at = where_of(&s.host, &s.r#where);
        if hosted.contains(&at) {
            lines.insert(format!("{}: set for {at}, which deploys on {}, so {} stores it", s.value, vendor.name, vendor.name));
        }
    }
    for (key, places) in map {
        let prefix = format!("{}:", vendor.id);
        let there = places.iter().any(|p| p.vendor.as_deref() == Some(vendor.id.as_str()) || p.place.to_lowercase().starts_with(&prefix));
        if there || env_match(env, key) {
            lines.insert(format!("{key}: stored at {} (rotation map)", places.iter().map(|p| p.place.as_str()).collect::<Vec<_>>().join(", ")));
        }
    }
    lines.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VendorConfig;
    use crate::vendors::catalog::VendorFeedKind;

    fn config(vendors: Vec<VendorConfig>, ignore: &[&str]) -> Config {
        let raw = serde_json::json!({ "collectors": [{ "type": "host" }] });
        let mut config = crate::config::build_config(&raw, std::path::Path::new("/x/config.json"), &Default::default()).expect("builds");
        config.vendors = vendors;
        config.ignore_vendors = ignore.iter().map(|s| (*s).to_string()).collect();
        config
    }

    fn inventory(signals: serde_json::Value, items: serde_json::Value, secrets: serde_json::Value) -> Inventory {
        serde_json::from_value(serde_json::json!({ "collectedAt": "2026-10-22T00:00:00.000Z", "signals": signals, "items": items, "secrets": secrets }))
            .expect("parses")
    }

    #[test]
    fn detects_from_signals_items_and_config_and_honours_ignore() {
        let inv = inventory(
            serde_json::json!([
                { "host": "github", "where": "repo:acme/web", "kind": "file", "value": "vercel.json" },
                { "host": "github", "where": "repo:acme/web", "kind": "env", "value": "VERCEL_TOKEN" },
                { "host": "github", "where": "repo:acme/api", "kind": "env", "value": "STRIPE_API_KEY" }
            ]),
            serde_json::json!([{ "host": "github", "where": "repo:acme/web", "kind": "platform", "name": "vercel", "version": "-" }]),
            serde_json::json!([]),
        );
        let vendors = detect_vendors(
            &inv,
            &config(
                vec![VendorConfig {
                    id: "acme".into(),
                    name: Some("Acme Cloud".into()),
                    aliases: vec![],
                    feeds: vec![VendorFeed { url: "https://status.example.com/rss".into(), kind: VendorFeedKind::Status }],
                }],
                &["stripe"],
            ),
        );
        assert_eq!(vendors.iter().map(|v| v.id.as_str()).collect::<Vec<_>>(), ["acme", "vercel"], "sorted by id; stripe is ignored");
        let acme = &vendors[0];
        assert!(acme.manual);
        assert_eq!(
            (acme.name.as_str(), acme.aliases.as_slice(), acme.evidence.as_slice()),
            ("Acme Cloud", &["acme cloud".to_string()][..], &["named in the config".to_string()][..])
        );
        let vercel = &vendors[1];
        assert_eq!(
            vercel.hosting,
            [Place { host: "github".into(), r#where: "repo:acme/web".into() }],
            "a config file and a platform item mean it deploys there, one place"
        );
        assert_eq!(vercel.evidence[0], "github repo:acme/web vercel.json");
        assert!(vercel.evidence.contains(&"github repo:acme/web env VERCEL_TOKEN".to_string()));
    }

    #[test]
    fn rotation_lists_names_and_places_never_values() {
        let inv = inventory(
            serde_json::json!([
                { "host": "github", "where": "repo:acme/web", "kind": "file", "value": "vercel.json" },
                { "host": "github", "where": "repo:acme/web", "kind": "env", "value": "DATABASE_URL" },
                { "host": "github", "where": "repo:acme/web", "kind": "env", "value": "VERSION" },
                { "host": "github", "where": "repo:acme/web", "kind": "env", "value": "PUBLIC_SITE_URL" },
                { "host": "github", "where": "repo:acme/web", "kind": "env", "value": "DEPLOY_HOOK_ID", "path": "actions" }
            ]),
            serde_json::json!([]),
            serde_json::json!([{ "host": "github", "where": "repo:acme/web", "location": ".env", "kind": "env-file", "name": "VERCEL_TOKEN", "fingerprint": "abcd1234", "exposure": "committed-env-file", "risk": "committed", "providers": ["vercel"] }]),
        );
        let vendors = detect_vendors(&inv, &config(vec![], &[]));
        let vercel = vendors.iter().find(|v| v.id == "vercel").expect("detected from vercel.json");
        let mut map = RotationMap::new();
        map.insert("API_KEY".into(), vec![RotationPlace { place: "vercel:acme-web (production)".into(), vendor: None }]);
        map.insert("OTHER".into(), vec![RotationPlace { place: "fly:acme-api".into(), vendor: Some("fly".into()) }]);
        assert_eq!(
            rotation_for(vercel, &inv, &map),
            [
                "VERCEL_TOKEN (fp abcd1234): belongs to Vercel; stored at github repo:acme/web .env",
                "DATABASE_URL: set for github repo:acme/web, which deploys on Vercel, so Vercel stores it",
                "DEPLOY_HOOK_ID: set for github repo:acme/web, which deploys on Vercel, so Vercel stores it",
                "API_KEY: stored at vercel:acme-web (production) (rotation map)"
            ]
        );
    }

    #[test]
    fn candidates_follow_the_vendor_feed_or_a_headline_that_names_the_vendor() {
        let vendor = |id: &str, alias: &str| UserVendor {
            id: id.into(),
            name: id.into(),
            aliases: vec![alias.into()],
            feeds: vec![],
            evidence: vec![],
            places: vec![],
            hosting: vec![],
            manual: false,
        };
        let item = |source: &str, id: &str, title: &str, vendor: Option<&str>, news: bool| ProseItem {
            source: source.into(),
            id: id.into(),
            title: title.into(),
            text: "text".into(),
            url: "u".into(),
            published: None,
            cves: vec![],
            exploited: None,
            high_signal: false,
            changed: None,
            vendor: vendor.map(String::from),
            news: news.then_some(true),
        };
        let vendors = [vendor("vercel", "vercel"), vendor("fly", "fly.io")];
        let items = [
            item("vendor:vercel:status", "1", "Elevated errors", Some("vercel"), false),
            item("news", "2", "Fly.io discloses a breach", None, true),
            item("news", "3", "A tutorial about gardening", None, true),
            item("feed", "4", "Vercel mentioned in a plain feed", None, false),
            ProseItem {
                cves: vec!["CVE-2026-1234".into()],
                ..item("vendor:vercel:security", "5", "CVE-2026-1234 Vercel CLI path traversal", Some("vercel"), false)
            },
            ProseItem {
                text: "Attackers used stolen Fly.io tokens to publish it.".into(),
                ..item("news", "6", "Supply chain attack hits PromptRouter", None, true)
            },
        ];
        let got = vendor_candidates(&items, &vendors);
        assert_eq!(got.iter().map(|c| (c.vendor.id.as_str(), c.items[0].id.as_str())).collect::<Vec<_>>(), [("vercel", "1"), ("fly", "2")]);
        assert_eq!(vendor_input(&got[1]), "[news] Fly.io discloses a breach\ntext");
        assert_eq!(
            vendor_sources(&[UserVendor {
                feeds: vec![VendorFeed { url: "a".into(), kind: VendorFeedKind::Status }, VendorFeed { url: "b".into(), kind: VendorFeedKind::Security }],
                ..vendors[0].clone()
            }])
            .iter()
            .map(|s| s.id.as_str())
            .collect::<Vec<_>>(),
            ["vendor:vercel:status", "vendor:vercel:security-1"]
        );
    }
}
