// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! What a response judged, kept on its case: each affected item with the version it ran at and the exposure of
//! its place. A vulnerability already judged at that version and exposure is not judged again when it returns by
//! some other route (it matches the inventory again, a service stops and starts); only a material change is
//! (exploitation in the wild, a fix shipping, the installed version or the exposure changing). A *new*
//! vulnerability is never skipped: it has no record here.

use serde::{Deserialize, Serialize};

use crate::types::Inventory;
use crate::watch::{Affected, Case};

/// One affected item as it was when judged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JudgedItem {
    pub host: String,
    pub r#where: String,
    pub name: String,
    pub version: String,
    /// The public hostnames and ports of its place, sorted; empty: not reachable from outside as far as the host shows.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub exposure: String,
}

/// The facts a response judged a case at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Judged {
    pub at: String,
    /// Exploited in the wild when it was judged.
    #[serde(default)]
    pub exploited: bool,
    /// A fixed release existed when it was judged.
    #[serde(default)]
    pub fix_available: bool,
    pub items: Vec<JudgedItem>,
    /// Every place the case covered, as `host where`: a place beyond the capped item list was still judged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub places: Vec<String>,
}

/// What reaches a place from outside, as one comparable string: its public hostnames and ports, sorted.
pub fn exposure_of(inventory: &Inventory, host: &str, place: &str) -> String {
    let mut exposed: Vec<&str> =
        inventory.services.iter().filter(|s| s.host == host && s.r#where == place).flat_map(|s| s.exposed.iter().map(String::as_str)).collect();
    exposed.sort_unstable();
    exposed.dedup();
    exposed.join(", ")
}

fn same_item(a: &Affected, host: &str, place: &str, name: &str) -> bool {
    a.host == host && a.r#where == place && a.name == name
}

impl Judged {
    /// The case as a response is about to see it: every affected item at the version and exposure it has now.
    /// `None` when the case names no item (a vendor incident, a CA).
    pub fn snapshot(c: &Case, inventory: &Inventory, at: &str) -> Option<Self> {
        let affected = c.affected.as_deref().filter(|a| !a.is_empty())?;
        let mut items: Vec<JudgedItem> = Vec::new();
        for a in affected {
            let item = JudgedItem {
                host: a.host.clone(),
                r#where: a.r#where.clone(),
                name: a.name.clone(),
                version: a.version.clone(),
                exposure: exposure_of(inventory, &a.host, &a.r#where),
            };
            if !items.contains(&item) {
                items.push(item);
            }
        }
        let places = c.places.iter().map(|p| format!("{} {}", p.host, p.r#where)).collect();
        Some(Self { at: at.to_string(), exploited: c.exploited == Some(true), fix_available: c.fix_available, items, places })
    }

    /// Whether `c` still stands as judged: nothing material changed. Exploitation or a fix that was not there when
    /// it was judged, an item (or a place) the judgement never saw, an item no longer at the judged version, or a
    /// place whose exposure changed all say no; an item gone from the inventory says nothing.
    pub fn covers(&self, c: &Case, inventory: &Inventory) -> bool {
        if (c.exploited == Some(true) && !self.exploited) || (c.fix_available && !self.fix_available) {
            return false;
        }
        let affected = c.affected.as_deref().unwrap_or_default();
        if affected.is_empty() {
            return false;
        }
        for a in affected {
            let present: Vec<&str> =
                inventory.items.iter().filter(|i| i.host == a.host && i.r#where == a.r#where && i.name == a.name).map(|i| i.version.as_str()).collect();
            if present.is_empty() {
                continue;
            }
            let exposure = exposure_of(inventory, &a.host, &a.r#where);
            let judged = |i: &&JudgedItem| i.host == a.host && i.r#where == a.r#where && i.name == a.name;
            // The item must have been judged, at a version it still runs, with the exposure it has now.
            if !self.items.iter().filter(judged).any(|j| present.contains(&j.version.as_str()) && j.exposure == exposure) {
                return false;
            }
        }
        true
    }

    /// Whether the place was part of what was judged.
    pub fn judged_place(&self, host: &str, place: &str) -> bool {
        self.places.iter().any(|p| *p == format!("{host} {place}")) || self.items.iter().any(|i| i.host == host && i.r#where == place)
    }

    /// The judged items that are about the same package and place as `c`'s affected items.
    pub fn overlap<'a>(&'a self, c: &Case) -> Vec<&'a JudgedItem> {
        let affected = c.affected.as_deref().unwrap_or_default();
        self.items.iter().filter(|j| affected.iter().any(|a| same_item(a, &j.host, &j.r#where, &j.name))).collect()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn inventory(version: &str, exposed: &[&str]) -> Inventory {
        serde_json::from_value(json!({
            "collectedAt": "2026-10-21T06:00:00Z", "sources": {},
            "items": [{ "host": "web1", "where": "container:api", "kind": "package", "ecosystem": "npm", "name": "left-pad", "version": version }],
            "services": [{ "host": "web1", "where": "container:api", "state": "running", "exposed": exposed }]
        }))
        .expect("an inventory")
    }

    fn case(extra: serde_json::Value) -> Case {
        let mut raw = json!({
            "key": "CVE-2026-1", "kind": "vulnerability", "title": "t", "state": "handled", "reason": "high", "severity": "high", "fixAvailable": false,
            "firstSeen": "", "updatedAt": "", "places": [{ "host": "web1", "where": "container:api" }],
            "affected": [{ "host": "web1", "where": "container:api", "name": "left-pad", "version": "1.0.0" }]
        });
        raw.as_object_mut().expect("an object").extend(extra.as_object().cloned().unwrap_or_default());
        serde_json::from_value(raw).expect("a case")
    }

    fn judged_at(inventory: &Inventory, c: &Case) -> Judged {
        Judged::snapshot(c, inventory, "2026-10-21T08:00:00Z").expect("a snapshot")
    }

    #[test]
    fn a_judgement_stands_until_the_version_the_exposure_exploitation_or_a_fix_changes() {
        let (inv, c) = (inventory("1.0.0", &["api.example.com"]), case(json!({})));
        let j = judged_at(&inv, &c);
        assert!(j.covers(&c, &inv), "nothing changed");
        assert!(!j.covers(&c, &inventory("0.9.0", &["api.example.com"])), "another installed version");
        assert!(!j.covers(&c, &inventory("1.0.0", &[])), "no longer public");
        assert!(!j.covers(&c, &inventory("1.0.0", &["api.example.com", "api.example.org"])), "a new hostname");
        assert!(!j.covers(&case(json!({ "exploited": true })), &inv), "exploitation in the wild");
        assert!(!j.covers(&case(json!({ "fixAvailable": true })), &inv), "a fix");
        assert!(j.covers(&case(json!({})), &inventory("1.0.0", &["api.example.com"])), "a fixed copy next to it changes nothing");
    }

    #[test]
    fn an_item_the_judgement_never_saw_is_judged_and_one_gone_from_the_inventory_is_not_asked_about() {
        let (inv, c) = (inventory("1.0.0", &[]), case(json!({})));
        let j = judged_at(&inv, &c);
        let wider = case(json!({ "affected": [
            { "host": "web1", "where": "container:api", "name": "left-pad", "version": "1.0.0" },
            { "host": "web1", "where": "container:api", "name": "right-pad", "version": "2.0.0" },
        ] }));
        let with_right_pad: Inventory = {
            let mut v = serde_json::to_value(&inv).expect("serializes");
            v["items"]
                .as_array_mut()
                .expect("items")
                .push(json!({ "host": "web1", "where": "container:api", "kind": "package", "name": "right-pad", "version": "2.0.0" }));
            serde_json::from_value(v).expect("an inventory")
        };
        assert!(!j.covers(&wider, &with_right_pad), "right-pad was never judged here");
        assert!(j.covers(&wider, &inv), "right-pad is not installed: nothing to judge");
    }
}
