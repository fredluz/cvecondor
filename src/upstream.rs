// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! Fixed releases named upstream, before every ecosystem's database maps them. The CVE record, the vendors'
//! release notes, distro trackers and security news name the fixed versions days before OSV maps each
//! ecosystem. Which products carry the vulnerable code and which of their releases fix it is judgment: the
//! responder reads the sources and writes one line per component in a fenced `<NAME>-fixed` block of its
//! report. Matching those lines against the inventory is this module: an item below the fix on its own line
//! moves to that release, an item on a line that gets no fix moves to a supported line, an item on a fixed
//! release or newer is left alone, and a component with no fixed release yet is affected and waits.

use std::cmp::Ordering;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::matching::osv_family;
use crate::name::NAME;
use crate::types::{InventoryItem, ItemKind};
use crate::versions::{compare_dpkg, compare_loose};

/// One component that carries the vulnerable code, and the first release of each of its lines that has the fix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixedRelease {
    /// A runtime by its inventory name (`node`, `bun`, `python`), wherever it runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// `<ecosystem>:<name>`, split at the last `:`: a language package (`PyPI:Brotli`, `npm:undici`) or a distro's
    /// package by its source or binary name (`Alpine:brotli`, `Debian:12:brotli`). An ecosystem without a release
    /// (`Debian`) covers all of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    /// The first fixed release of each line; empty: no fixed release yet.
    #[serde(default)]
    pub fixed: Vec<String>,
}

/// What a fixed release says about one item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reading {
    /// On a fixed release of its line, or newer than every fixed release.
    Fixed,
    /// Below the fix on its own line: this release fixes it.
    Update(String),
    /// Its line gets no fix: move to a supported line, from this release on.
    MoveLine(String),
    /// Affected, and no fixed release yet.
    NoFix,
}

/// The numeric lead of a version: a leading `v` and a dpkg epoch dropped, then `1.2.3` up to the first other character.
fn lead(version: &str) -> Option<Vec<u64>> {
    let v = version.trim().trim_start_matches(['v', 'V']);
    let v = match v.split_once(':') {
        Some((epoch, rest)) if !epoch.is_empty() && epoch.bytes().all(|b| b.is_ascii_digit()) => rest,
        _ => v,
    };
    let end = v.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(v.len());
    let nums: Vec<u64> = v[..end].split('.').map_while(|s| s.parse().ok()).collect();
    (!nums.is_empty()).then_some(nums)
}

/// PyPI names compare normalised (`Foo_Bar` is `foo-bar`); everything else by case only.
fn same_name(ecosystem: &str, a: &str, b: &str) -> bool {
    let norm = |s: &str| if osv_family(ecosystem).eq_ignore_ascii_case("PyPI") { s.to_lowercase().replace(['_', '.'], "-") } else { s.to_lowercase() };
    norm(a) == norm(b)
}

impl FixedRelease {
    fn package_parts(&self) -> Option<(&str, &str)> {
        self.package.as_deref()?.rsplit_once(':').filter(|(e, n)| !e.is_empty() && !n.is_empty())
    }

    /// A runtime or a package, not both; every fixed release starts with a version number.
    fn valid(&self) -> bool {
        let runtime = self.runtime.as_deref().is_some_and(|r| !r.trim().is_empty());
        runtime != self.package_parts().is_some() && self.fixed.iter().all(|f| lead(f).is_some())
    }

    /// `node fixed in 22.23.4 / 24.22.1`, `Debian brotli: no fixed release yet`.
    pub fn describe(&self) -> String {
        let what = match (&self.runtime, self.package_parts()) {
            (Some(runtime), _) => runtime.clone(),
            (None, Some((ecosystem, name))) => format!("{ecosystem} {name}"),
            (None, None) => String::new(),
        };
        if self.fixed.is_empty() { format!("{what}: no fixed release yet") } else { format!("{what} fixed in {}", self.fixed.join(" / ")) }
    }

    /// Whether the item is this component: the runtime by name, a package by ecosystem (or its family) and name, a
    /// distro package by its source name or the binary name it was read under.
    pub fn covers(&self, item: &InventoryItem) -> bool {
        if let Some(runtime) = &self.runtime {
            return item.kind == ItemKind::Runtime && item.name.eq_ignore_ascii_case(runtime.trim());
        }
        let Some((ecosystem, name)) = self.package_parts() else { return false };
        let Some(item_ecosystem) = item.ecosystem.as_deref() else { return false };
        if !(item_ecosystem.eq_ignore_ascii_case(ecosystem) || osv_family(item_ecosystem).eq_ignore_ascii_case(ecosystem)) {
            return false;
        }
        match item.kind {
            ItemKind::Package => same_name(item_ecosystem, &item.name, name),
            ItemKind::OsPackage => item.name.eq_ignore_ascii_case(name) || item.path.as_deref().is_some_and(|p| p.eq_ignore_ascii_case(name)),
            _ => false,
        }
    }

    /// The item's version against the fixed releases; `None` when it has no version number (`latest`). A line is
    /// the major version, or major.minor when two fixed releases share a major (`1.0.10`, `1.1.1`, `1.2.1`).
    pub fn read(&self, item: &InventoryItem) -> Option<Reading> {
        let version = lead(&item.version)?;
        if self.fixed.is_empty() {
            return Some(Reading::NoFix);
        }
        let debian = item.ecosystem.as_deref().map(osv_family).is_some_and(|f| matches!(f, "Debian" | "Ubuntu"));
        let cmp = |a: &str, b: &str| if debian { compare_dpkg(a, b) } else { compare_loose(a, b) };
        let mut fixed: Vec<&String> = self.fixed.iter().collect();
        fixed.sort_by(|a, b| cmp(a, b));
        let leads: Vec<Vec<u64>> = fixed.iter().filter_map(|f| lead(f)).collect();
        let shared_major = leads.iter().enumerate().any(|(i, a)| leads[i + 1..].iter().any(|b| a[0] == b[0]));
        let depth = if shared_major { 2 } else { 1 };
        let line = |nums: &[u64]| nums.iter().take(depth).copied().collect::<Vec<_>>();
        let at_or_above = |f: &str| cmp(&item.version, f) != Ordering::Less;
        if let Some(f) = fixed.iter().find(|f| lead(f).is_some_and(|l| line(&l) == line(&version))) {
            return Some(if at_or_above(f) { Reading::Fixed } else { Reading::Update((*f).clone()) });
        }
        if fixed.last().is_some_and(|newest| at_or_above(newest)) {
            return Some(Reading::Fixed);
        }
        fixed.iter().find(|f| !at_or_above(f)).map(|f| Reading::MoveLine((*f).clone()))
    }
}

/// The fenced ```` ```<NAME>-fixed ```` blocks of a report.
static FIXED_BLOCK: LazyLock<Regex> = LazyLock::new(|| Regex::new(&format!(r"(?s)```{}-fixed\s*\n(.*?)```", regex::escape(NAME))).expect("valid regex"));

/// Parses the fixed releases a responder read from the sources: a fenced block tagged `<NAME>-fixed`, one JSON
/// object per line: `{"runtime": "node", "fixed": ["22.23.4", "24.22.1"]}`, `{"package": "PyPI:Brotli", "fixed": ["1.2.1"]}`,
/// `{"package": "Debian:brotli", "fixed": []}`. Lines that don't parse or name no component are skipped; two lines for
/// one component are one.
pub fn parse_fixed(report: &str) -> Vec<FixedRelease> {
    let mut out: Vec<FixedRelease> = Vec::new();
    for block in FIXED_BLOCK.captures_iter(report) {
        for line in block[1].split('\n') {
            let Ok(release) = serde_json::from_str::<FixedRelease>(line.trim()) else { continue };
            if !release.valid() {
                continue;
            }
            match out.iter_mut().find(|r| r.runtime == release.runtime && r.package == release.package) {
                Some(known) => {
                    for f in release.fixed {
                        if !known.fixed.contains(&f) {
                            known.fixed.push(f);
                        }
                    }
                }
                None => out.push(release),
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(kind: ItemKind, ecosystem: Option<&str>, name: &str, version: &str, path: Option<&str>) -> InventoryItem {
        InventoryItem {
            host: "web1".into(),
            r#where: "container:x".into(),
            kind,
            ecosystem: ecosystem.map(str::to_string),
            name: name.into(),
            version: version.into(),
            path: path.map(str::to_string),
            running: None,
            dev: None,
            collector: None,
        }
    }

    fn runtime(name: &str, fixed: &[&str]) -> FixedRelease {
        FixedRelease { runtime: Some(name.into()), package: None, fixed: fixed.iter().map(|f| (*f).to_string()).collect() }
    }

    fn package(package: &str, fixed: &[&str]) -> FixedRelease {
        FixedRelease { runtime: None, package: Some(package.into()), fixed: fixed.iter().map(|f| (*f).to_string()).collect() }
    }

    fn read(release: &FixedRelease, version: &str) -> Option<Reading> {
        release.read(&item(ItemKind::Runtime, None, "node", version, None))
    }

    #[test]
    fn node_lines_are_majors_an_end_of_life_line_moves_and_a_fixed_or_newer_release_is_left_alone() {
        let node = runtime("node", &["22.23.4", "24.22.1", "26.12.1"]);
        assert_eq!(read(&node, "22.23.2"), Some(Reading::Update("22.23.4".into())));
        assert_eq!(read(&node, "22"), Some(Reading::Update("22.23.4".into())), "a floating major tag moves to the fix");
        assert_eq!(read(&node, "v24.1.0"), Some(Reading::Update("24.22.1".into())));
        assert_eq!(read(&node, "22.23.4"), Some(Reading::Fixed));
        assert_eq!(read(&node, "22.24.0"), Some(Reading::Fixed), "later on the same line");
        assert_eq!(read(&node, "26.12.1"), Some(Reading::Fixed));
        assert_eq!(read(&node, "27.0.0"), Some(Reading::Fixed), "newer than every fixed line");
        assert_eq!(read(&node, "20.19.6"), Some(Reading::MoveLine("22.23.4".into())));
        assert_eq!(read(&node, "23.11.0"), Some(Reading::MoveLine("24.22.1".into())));
        assert_eq!(read(&node, "25.9.0"), Some(Reading::MoveLine("26.12.1".into())));
        assert_eq!(read(&node, "latest"), None);
    }

    #[test]
    fn fixed_releases_sharing_a_major_make_major_minor_lines_and_a_single_fix_covers_its_whole_major() {
        let brotli = runtime("node", &["1.2.1", "1.0.10", "1.1.1"]);
        assert_eq!(read(&brotli, "1.1.0"), Some(Reading::Update("1.1.1".into())));
        assert_eq!(read(&brotli, "1.0.12"), Some(Reading::Fixed));
        assert_eq!(read(&brotli, "1.2.0"), Some(Reading::Update("1.2.1".into())));
        assert_eq!(read(&brotli, "0.9.0"), Some(Reading::MoveLine("1.0.10".into())));
        let bun = runtime("node", &["1.4.4"]);
        assert_eq!(read(&bun, "1.3.5"), Some(Reading::Update("1.4.4".into())));
        assert_eq!(read(&bun, "1.4.4"), Some(Reading::Fixed));
        assert_eq!(read(&bun, "1.5.0"), Some(Reading::Fixed));
        assert_eq!(read(&runtime("node", &[]), "1.4.4"), Some(Reading::NoFix));
    }

    #[test]
    fn distro_packages_compare_by_their_own_rules_and_match_by_source_or_binary_name() {
        let alpine = package("Alpine:brotli-libs", &["1.2.1-r0"]);
        let libs = item(ItemKind::OsPackage, Some("Alpine:v3.22"), "brotli", "1.2.0-r0", Some("brotli-libs"));
        assert!(alpine.covers(&libs), "the binary name it was read under");
        assert_eq!(alpine.read(&libs), Some(Reading::Update("1.2.1-r0".into())));
        assert_eq!(alpine.read(&item(ItemKind::OsPackage, Some("Alpine:v3.22"), "brotli", "1.2.1-r1", None)), Some(Reading::Fixed));
        assert!(!alpine.covers(&item(ItemKind::OsPackage, Some("Debian:12"), "brotli", "1.0.9-2", None)), "another distro");

        let debian = package("Debian:12:brotli", &["1.0.9-2+deb12u1"]);
        let lib = item(ItemKind::OsPackage, Some("Debian:12"), "brotli", "1.0.9-2+b6", Some("libbrotli1"));
        assert!(debian.covers(&lib));
        assert!(!debian.covers(&item(ItemKind::OsPackage, Some("Debian:13"), "brotli", "1.1.0-2", None)), "another release");
        assert_eq!(debian.read(&lib), Some(Reading::Update("1.0.9-2+deb12u1".into())), "dpkg order: +b6 sorts before +deb12u1");
        assert_eq!(package("Debian:brotli", &[]).read(&lib), Some(Reading::NoFix));
    }

    #[test]
    fn language_packages_match_by_ecosystem_and_normalised_name_never_a_runtime_or_another_ecosystem() {
        let pypi = package("PyPI:Brotli", &["1.2.1"]);
        assert!(pypi.covers(&item(ItemKind::Package, Some("PyPI"), "brotli", "1.2.0", None)));
        assert!(package("PyPI:brotli_cffi", &["1.2.1.0"]).covers(&item(ItemKind::Package, Some("PyPI"), "brotli-cffi", "1.2.0.1", None)));
        assert!(!pypi.covers(&item(ItemKind::Package, Some("npm"), "brotli", "1.2.0", None)));
        assert!(!pypi.covers(&item(ItemKind::Runtime, None, "brotli", "1.2.0", None)));
        assert!(!runtime("bun", &["1.4.4"]).covers(&item(ItemKind::Package, Some("npm"), "bun", "1.3.0", None)));
    }

    #[test]
    fn the_fixed_block_is_read_line_by_line_and_bad_lines_are_skipped() {
        let report = format!(
            "## Message\nsplit\n\n```{NAME}-fixed\n{{\"runtime\": \"node\", \"fixed\": [\"22.23.4\", \"24.22.1\"]}}\n{{\"runtime\": \"node\", \"fixed\": [\"26.12.1\"]}}\nnot json\n{{\"package\": \"PyPI:Brotli\", \"fixed\": [\"1.2.1\"]}}\n{{\"package\": \"Debian:brotli\", \"fixed\": []}}\n{{\"package\": \"nocolon\", \"fixed\": [\"1\"]}}\n{{\"runtime\": \"bun\", \"package\": \"npm:bun\", \"fixed\": [\"1\"]}}\n{{\"runtime\": \"bun\", \"fixed\": [\"soon\"]}}\n```\n\n```{NAME}-wait\n{{\"runtime\": \"deno\", \"fixed\": [\"2\"]}}\n```\n"
        );
        let fixed = parse_fixed(&report);
        assert_eq!(fixed, [runtime("node", &["22.23.4", "24.22.1", "26.12.1"]), package("PyPI:Brotli", &["1.2.1"]), package("Debian:brotli", &[])]);
        assert_eq!(fixed[0].describe(), "node fixed in 22.23.4 / 24.22.1 / 26.12.1");
        assert_eq!(fixed[2].describe(), "Debian brotli: no fixed release yet");
    }
}
