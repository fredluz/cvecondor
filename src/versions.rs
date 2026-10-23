// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! Version comparison for the CVE watch: Debian/Ubuntu (dpkg), Alpine (apk),
//! and a semver-like scheme for runtimes and language packages. OSV settles
//! package ranges itself; these cover the sources that only give a range string.

use std::cmp::Ordering;
use std::sync::LazyLock;

use anyhow::{Result, anyhow};
use regex::Regex;

/// JS `Number(text)` for a run of digits (`NaN` when it is not a number).
fn js_number(text: &str) -> f64 {
    if text.is_empty() { 0.0 } else { text.parse().unwrap_or(f64::NAN) }
}

/// JS number-to-string for the integers and `NaN` this module builds versions from.
fn js_string(n: f64) -> String {
    if n.is_nan() {
        "NaN".to_string()
    } else if n.fract() == 0.0 && n.abs() < 1e21 {
        format!("{}", n as i128)
    } else {
        n.to_string()
    }
}

fn sign(d: f64) -> Ordering {
    if d > 0.0 {
        Ordering::Greater
    } else if d < 0.0 {
        Ordering::Less
    } else {
        Ordering::Equal
    }
}

/// dpkg's ordering: epoch, then upstream and revision by alternating non-digit/digit runs, `~` sorting first.
pub fn compare_dpkg(a: &str, b: &str) -> Ordering {
    fn split(v: &str) -> (f64, &str, &str) {
        let colon = v.find(':').filter(|&c| c > 0);
        let epoch = match colon {
            Some(c) if v[..c].bytes().all(|b| b.is_ascii_digit()) => js_number(&v[..c]),
            _ => 0.0,
        };
        let rest = colon.map_or(v, |c| &v[c + 1..]);
        match rest.rfind('-').filter(|&d| d > 0) {
            Some(d) => (epoch, &rest[..d], &rest[d + 1..]),
            None => (epoch, rest, "0"),
        }
    }

    fn order(c: Option<char>) -> i64 {
        match c {
            Some('~') => -1,
            Some(c) if c.is_ascii_alphabetic() => i64::from(c as u32),
            Some(c) => i64::from(c as u32) + 256,
            None => 0,
        }
    }

    fn part(x: &str, y: &str) -> Ordering {
        let (x, y): (Vec<char>, Vec<char>) = (x.chars().collect(), y.chars().collect());
        let (mut i, mut j) = (0, 0);
        while i < x.len() || j < y.len() {
            while (i < x.len() && !x[i].is_ascii_digit()) || (j < y.len() && !y[j].is_ascii_digit()) {
                let cx = x.get(i).copied().filter(|c| !c.is_ascii_digit());
                let cy = y.get(j).copied().filter(|c| !c.is_ascii_digit());
                let d = order(cx) - order(cy);
                if d != 0 {
                    return d.cmp(&0);
                }
                if cx.is_some() {
                    i += 1;
                }
                if cy.is_some() {
                    j += 1;
                }
                if cx.is_none() && cy.is_none() {
                    break;
                }
            }
            let (mut nx, mut ny) = (String::new(), String::new());
            while i < x.len() && x[i].is_ascii_digit() {
                nx.push(x[i]);
                i += 1;
            }
            while j < y.len() && y[j].is_ascii_digit() {
                ny.push(y[j]);
                j += 1;
            }
            let d = sign(js_number(&nx) - js_number(&ny));
            if d != Ordering::Equal {
                return d;
            }
        }
        Ordering::Equal
    }

    let ((ea, ua, ra), (eb, ub, rb)) = (split(a), split(b));
    sign(ea - eb).then_with(|| part(ua, ub)).then_with(|| part(ra, rb))
}

/// Numeric dot segments compared as numbers, then a prerelease (`-rc.1`, `rc1`) sorts before its release.
pub fn compare_loose(a: &str, b: &str) -> Ordering {
    struct Parsed {
        nums: Vec<f64>,
        pre: String,
    }

    fn parse(v: &str) -> Parsed {
        let trimmed = v.trim();
        let clean = trimmed.strip_prefix(['v', 'V']).unwrap_or(trimmed);
        let clean = clean.split('+').next().unwrap_or_default();
        let digits_end = clean.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(clean.len());
        if digits_end == 0 {
            return Parsed { nums: Vec::new(), pre: clean.to_string() };
        }
        let nums = clean[..digits_end].split('.').filter(|s| !s.is_empty()).map(js_number).collect();
        let rest = &clean[digits_end..];
        Parsed { nums, pre: rest.strip_prefix(['-', '.', '_']).unwrap_or(rest).to_string() }
    }

    // Alpine's `-r4` is a revision, not a prerelease.
    fn revision(pre: &str) -> Option<f64> {
        pre.strip_prefix('r').filter(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit())).map(js_number)
    }

    let (x, y) = (parse(a), parse(b));
    for i in 0..x.nums.len().max(y.nums.len()) {
        let d = sign(x.nums.get(i).copied().unwrap_or(0.0) - y.nums.get(i).copied().unwrap_or(0.0));
        if d != Ordering::Equal {
            return d;
        }
    }
    let (rx, ry) = (revision(&x.pre), revision(&y.pre));
    if rx.is_some() || ry.is_some() {
        return sign(rx.unwrap_or(0.0) - ry.unwrap_or(0.0));
    }
    if x.pre == y.pre {
        Ordering::Equal
    } else if x.pre.is_empty() {
        Ordering::Greater
    } else if y.pre.is_empty() {
        Ordering::Less
    } else {
        x.pre.cmp(&y.pre)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
}

struct Comparator {
    op: Op,
    version: String,
}

fn cmp(op: Op, version: impl Into<String>) -> Comparator {
    Comparator { op, version: version.into() }
}

static TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(<=|>=|<|>|=|\^|~)?\s*v?([0-9xX*]+(?:\.[0-9xX*]+){0,2})(-[0-9A-Za-z.-]+)?$").expect("valid regex"));

fn expand(token: &str) -> Result<Vec<Comparator>> {
    let m = TOKEN.captures(token).ok_or_else(|| anyhow!("unsupported version range '{token}'"))?;
    let op = m.get(1).map_or("", |g| g.as_str());
    let pre = m.get(3).map_or("", |g| g.as_str());
    let raw: Vec<&str> = m[2].split('.').collect();
    let wild = raw.iter().position(|p| matches!(*p, "x" | "X" | "*"));
    let parts: Vec<f64> = raw[..wild.unwrap_or(raw.len())].iter().map(|p| js_number(p)).collect();
    let join = |parts: &[f64]| parts.iter().map(|n| js_string(*n)).collect::<Vec<_>>().join(".");

    if wild.is_some() || parts.len() < 3 {
        // x-ranges and partial versions: `22.x`, `22`, `>=22`
        if parts.is_empty() {
            return Ok(if op == "<" || op == ">" { vec![cmp(Op::Lt, "0.0.0")] } else { Vec::new() });
        }
        let padded = |parts: &[f64]| join(&[parts, &[0.0, 0.0]].concat()[..3]);
        let low = padded(&parts);
        let mut high_parts = parts.clone();
        *high_parts.last_mut().expect("not empty") += 1.0;
        let high = padded(&high_parts);
        let next_major = format!("{}.0.0", js_string(parts[0] + 1.0));
        if op.is_empty() || op == "=" || (op == "^" && parts.len() == 1) || op == "~" {
            return Ok(if op == "^" && parts.len() > 1 && parts[0] > 0.0 {
                vec![cmp(Op::Ge, low), cmp(Op::Lt, next_major)]
            } else {
                vec![cmp(Op::Ge, low), cmp(Op::Lt, high)]
            });
        }
        return Ok(match op {
            "^" => vec![cmp(Op::Ge, low), cmp(Op::Lt, if parts[0] > 0.0 { next_major } else { high })],
            ">=" => vec![cmp(Op::Ge, low)],
            "<" => vec![cmp(Op::Lt, low)],
            ">" => vec![cmp(Op::Ge, high)],
            _ => vec![cmp(Op::Lt, high)],
        });
    }
    let v = format!("{}{pre}", join(&parts));
    let (maj, min) = (parts[0], parts[1]);
    Ok(match op {
        "^" => vec![cmp(Op::Ge, v), cmp(Op::Lt, if maj > 0.0 { format!("{}.0.0", js_string(maj + 1.0)) } else { format!("0.{}.0", js_string(min + 1.0)) })],
        "~" => vec![cmp(Op::Ge, v), cmp(Op::Lt, format!("{}.{}.0", js_string(maj), js_string(min + 1.0)))],
        "<=" => vec![cmp(Op::Le, v)],
        "<" => vec![cmp(Op::Lt, v)],
        ">=" => vec![cmp(Op::Ge, v)],
        ">" => vec![cmp(Op::Gt, v)],
        _ => vec![cmp(Op::Eq, v)],
    })
}

static OP_SPACE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(<=|>=|<|>|=|\^|~)\s+").expect("valid regex"));
static HYPHEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\S+)\s+-\s+(\S+)$").expect("valid regex"));

/// node-semver range syntax as used by the Node security-wg index: `22.x || ^24.18.1`, `>=1.2 <1.3`, `1.0.0 - 1.2.0`.
/// A range this module cannot read is an error (callers treat it as "does not match").
pub fn satisfies(version: &str, range: &str) -> Result<bool> {
    for alternative in range.split("||") {
        let text = OP_SPACE.replace_all(alternative.trim(), "$1");
        if text.is_empty() || text == "*" {
            return Ok(true);
        }
        let comparators = match HYPHEN.captures(&text) {
            Some(h) => vec![cmp(Op::Ge, &h[1]), cmp(Op::Le, &h[2])],
            None => text.split_whitespace().map(expand).collect::<Result<Vec<_>>>()?.into_iter().flatten().collect(),
        };
        let all = comparators.iter().all(|c| {
            let d = compare_loose(version, &c.version);
            match c.op {
                Op::Lt => d == Ordering::Less,
                Op::Le => d != Ordering::Greater,
                Op::Gt => d == Ordering::Greater,
                Op::Ge => d != Ordering::Less,
                Op::Eq => d == Ordering::Equal,
            }
        });
        if all {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders_debian_versions_and_node_ranges_the_way_dpkg_and_the_node_security_index_do() {
        assert_eq!(compare_dpkg("1.2.3~rc1-1", "1.2.3-1"), Ordering::Less);
        assert_eq!(compare_dpkg("2:9.1.0016-1ubuntu7", "9.2-1"), Ordering::Greater);
        let vulnerable = "22.x || 24.x || 26.x";
        let patched = "^22.23.4 || ^24.22.1 || ^26.12.1";
        let affected = |v: &str| satisfies(v, vulnerable).expect("range") && !satisfies(v, patched).expect("range");
        assert_eq!(["22.21.0", "22.23.2", "24.18.0", "22"].map(affected), [true, true, true, true]);
        assert_eq!(["22.23.4", "24.22.1", "26.12.1", "20.19.6"].map(affected), [false, false, false, false]);
    }

    #[test]
    fn dpkg_ordering_covers_revisions_epochs_and_tildes() {
        assert_eq!(compare_dpkg("1.0-1", "1.0-1"), Ordering::Equal);
        assert_eq!(compare_dpkg("1.0-2", "1.0-10"), Ordering::Less);
        assert_eq!(compare_dpkg("1.0-1ubuntu1", "1.0-1"), Ordering::Greater);
        assert_eq!(compare_dpkg("1:0.5-1", "9.9-1"), Ordering::Greater);
        assert_eq!(compare_dpkg("1.0+dfsg-1", "1.0-1"), Ordering::Greater);
        assert_eq!(compare_dpkg("1.0~~-1", "1.0~-1"), Ordering::Less);
        assert_eq!(compare_dpkg("a-b-1", "a-b-2"), Ordering::Less);
        assert_eq!(compare_dpkg("1.10", "1.9"), Ordering::Greater);
    }

    #[test]
    fn loose_ordering_handles_prereleases_v_prefixes_and_alpine_revisions() {
        assert_eq!(compare_loose("1.2.3", "1.2.3"), Ordering::Equal);
        assert_eq!(compare_loose("v1.10.0", "1.9.9"), Ordering::Greater);
        assert_eq!(compare_loose("1.2.3-rc.1", "1.2.3"), Ordering::Less);
        assert_eq!(compare_loose("1.2.3-rc.1", "1.2.3-rc.2"), Ordering::Less);
        assert_eq!(compare_loose("22", "22.0.0"), Ordering::Equal);
        assert_eq!(compare_loose("1.2.3+build5", "1.2.3"), Ordering::Equal);
        assert_eq!(compare_loose("1.2.3-r4", "1.2.3-r10"), Ordering::Less);
        assert_eq!(compare_loose("1.2.3-r1", "1.2.3"), Ordering::Greater);
    }

    #[test]
    fn satisfies_reads_node_semver_ranges() {
        let yes = |v: &str, r: &str| satisfies(v, r).expect("range");
        assert!(yes("1.2.5", ">=1.2 <1.3"));
        assert!(!yes("1.3.0", ">=1.2 <1.3"));
        assert!(yes("1.5.0", "1.0.0 - 1.9.9"));
        assert!(!yes("2.0.0", "1.0.0 - 1.9.9"));
        assert!(yes("0.2.9", "^0.2.3"));
        assert!(!yes("0.3.0", "^0.2.3"));
        assert!(yes("1.2.9", "~1.2.3"));
        assert!(!yes("1.3.0", "~1.2.3"));
        assert!(yes("9.9.9", "*"));
        assert!(yes("9.9.9", ""));
        assert!(yes("22.5.0", ">= 22"));
        assert!(!yes("21.9.9", ">= 22"));
        assert!(yes("22.5.0", "22.x"));
        assert!(!yes("23.0.0", "22"));
        assert!(yes("20.1.0", "< 22"));
        assert!(!yes("22.0.1", "> 22"), "`> 22` means `>= 23.0.0`");
        assert!(yes("23.0.0", "> 22"));
        assert!(!yes("22.0.0", "> 22"));
        assert!(yes("1.0.0", "<=1.0.0"));
        assert!(yes("3.0.0", "<2.0.0 || >=3.0.0"));
    }

    #[test]
    fn satisfies_reports_a_range_it_cannot_read() {
        let err = satisfies("1.0.0", "1.0.0 || not-a-range || 2.0.0");
        assert!(err.is_ok(), "an earlier alternative that matches settles it, as in the original");
        let err = satisfies("1.0.0", "2.0.0 || not-a-range").expect_err("unreadable");
        assert_eq!(err.to_string(), "unsupported version range 'not-a-range'");
    }
}
