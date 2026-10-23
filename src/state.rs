// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! The watcher's own state: JSON files in one directory, written atomically, owner-only.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// `None` when the file is missing or does not parse (the TS fallback). A file that exists but doesn't load is copied
/// to `<name>.bad` first, so the caller's next write never loses it.
pub fn read_state<T: DeserializeOwned>(dir: &Path, name: &str) -> Option<T> {
    let path = dir.join(name);
    let text = fs::read_to_string(&path).ok()?;
    match serde_json::from_str(&text) {
        Ok(value) => Some(value),
        Err(e) => {
            let bad = dir.join(format!("{name}.bad"));
            if fs::copy(&path, &bad).is_ok() {
                crate::util::log(&format!("{}: unreadable ({e}); kept a copy at {}", path.display(), bad.display()));
            }
            None
        }
    }
}

/// `JSON.stringify(value, null, 1) + "\n"`, written atomically.
pub fn write_state<T: Serialize + ?Sized>(dir: &Path, name: &str, value: &T) -> Result<()> {
    let mut buf = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b" ");
    let mut serializer = serde_json::Serializer::with_formatter(&mut buf, formatter);
    value.serialize(&mut serializer)?;
    buf.push(b'\n');
    write_file_atomic(&dir.join(name), &String::from_utf8(buf)?)
}

fn create_dir_private(dir: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)
}

/// Directories 0700, file 0600, written to `<file>.<pid>.tmp` and renamed into place.
pub fn write_file_atomic(file: &Path, content: &str) -> Result<()> {
    if let Some(parent) = file.parent().filter(|p| !p.as_os_str().is_empty()) {
        create_dir_private(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let mut temp = file.as_os_str().to_owned();
    temp.push(format!(".{}.tmp", std::process::id()));
    let temp = PathBuf::from(temp);
    let write = || -> std::io::Result<()> {
        use std::io::Write;
        let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&temp)?;
        f.write_all(content.as_bytes())?;
        fs::rename(&temp, file)
    };
    write().with_context(|| format!("write {}", file.display()))
}

struct LockGuard(PathBuf);

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// One cycle (or inventory refresh) at a time per state dir; a lock older than 30 minutes is a
/// crashed holder's. `None`: the lock is held.
pub fn with_lock<T>(dir: &Path, name: &str, run: impl FnOnce() -> T) -> Option<T> {
    let lock = dir.join(format!("{name}.lock"));
    let _ = create_dir_private(dir);
    if fs::create_dir(&lock).is_err() {
        let young = fs::metadata(&lock).and_then(|m| m.modified()).map(|t| t.elapsed().map_or(true, |age| age < Duration::from_secs(30 * 60))).unwrap_or(true);
        if young {
            return None;
        }
        let _ = fs::remove_dir_all(&lock);
        fs::create_dir(&lock).ok()?;
    }
    let _guard = LockGuard(lock);
    Some(run())
}

/// `*` (any run) and `?` (any one character), case-insensitive, against the whole value.
pub fn glob_match(pattern: &str, value: &str) -> bool {
    let p: Vec<char> = pattern.chars().flat_map(char::to_lowercase).collect();
    let v: Vec<char> = value.chars().flat_map(char::to_lowercase).collect();
    let (mut pi, mut vi) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while vi < v.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some((pi, vi));
            pi += 1;
        } else if pi < p.len() && (p[pi] == '?' || p[pi] == v[vi]) {
            pi += 1;
            vi += 1;
        } else if let Some((sp, sv)) = star {
            pi = sp + 1;
            vi = sv + 1;
            star = Some((sp, sv + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

/// A file-name-safe form of a case key: lower-case, runs of anything else become `-`, at most 48 characters.
pub fn slug(key: &str) -> String {
    let mut out = String::new();
    for c in key.to_lowercase().chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let trimmed = out.strip_prefix('-').unwrap_or(&out);
    let trimmed = trimmed.strip_suffix('-').unwrap_or(trimmed);
    let cut: String = trimmed.chars().take(48).collect();
    cut.strip_suffix('-').unwrap_or(&cut).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cvecondor-state-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn glob_match_is_whole_string_and_case_insensitive() {
        assert!(glob_match("acme/*", "acme/api"));
        assert!(glob_match("ACME/API", "acme/api"));
        assert!(glob_match("*", ""));
        assert!(glob_match("a?c", "abc"));
        assert!(glob_match("*.example.com", "api.example.com"));
        assert!(glob_match("a*b*c", "aXXbYYc"));
        assert!(!glob_match("acme/*", "other/acme/api"));
        assert!(!glob_match("api", "api.example.com"));
        assert!(!glob_match("a?c", "ac"));
        assert!(!glob_match("*b", "abc"));
        // Regex metacharacters in a pattern are literal.
        assert!(glob_match("a.c+(d)", "a.c+(d)"));
        assert!(!glob_match("a.c", "abc"));
    }

    #[test]
    fn slug_matches_the_ts_rules() {
        assert_eq!(slug("CVE-2026-1234"), "cve-2026-1234");
        assert_eq!(slug("vendor:vercel (incident #4)"), "vendor-vercel-incident-4");
        assert_eq!(slug("--Hello--"), "hello");
        assert_eq!(slug("***"), "");
        let long = format!("{}-tail", "a".repeat(47));
        assert_eq!(slug(&long), "a".repeat(47));
        assert_eq!(slug(&"b".repeat(60)), "b".repeat(48));
    }

    #[test]
    fn state_round_trips_in_one_space_pretty_json() {
        let dir = scratch("roundtrip");
        write_state(&dir, "x.json", &json!({ "a": [1, 2], "b": { "c": "d" }, "e": [], "f": {} })).expect("writes");
        let text = fs::read_to_string(dir.join("x.json")).expect("reads");
        assert_eq!(text, "{\n \"a\": [\n  1,\n  2\n ],\n \"b\": {\n  \"c\": \"d\"\n },\n \"e\": [],\n \"f\": {}\n}\n");
        let back: serde_json::Value = read_state(&dir, "x.json").expect("parses");
        assert_eq!(back["b"]["c"], "d");
        assert!(read_state::<serde_json::Value>(&dir, "missing.json").is_none());
        fs::write(dir.join("bad.json"), "{nope").expect("writes");
        assert!(read_state::<serde_json::Value>(&dir, "bad.json").is_none());
        fs::remove_dir_all(&dir).expect("cleans");
    }

    #[test]
    fn with_lock_refuses_a_second_holder_and_releases() {
        let dir = scratch("lock");
        let inner = with_lock(&dir, "cycle", || with_lock(&dir, "cycle", || 1)).expect("first holder runs");
        assert!(inner.is_none(), "a held lock is refused");
        assert_eq!(with_lock(&dir, "cycle", || 2), Some(2), "released after the run");
        fs::remove_dir_all(&dir).expect("cleans");
    }
}
