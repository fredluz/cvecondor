// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! Where everything that isn't urgent goes: not a push, but a file the agent in
//! charge reads when the user opens it. Each notice becomes a markdown file under
//! reports/ and one line in inbox.jsonl; `inbox` shows what is new since the agent
//! last read it, so it can summarise that in a few lines. Urgent notices are kept
//! here too, so the agent sees what interrupted the user.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Context, Result};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::notify::Notice;
use crate::state::{read_state, slug, write_file_atomic, write_state};
use crate::util::iso;

/// One line of `inbox.jsonl`: when a notice was kept, what it was, and the file that holds it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InboxEntry {
    pub at: String,
    pub event: String,
    pub title: String,
    pub file: String,
}

/// `inbox-read.json`: everything at or before `read_until` has been read.
#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReadMark {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    read_until: Option<String>,
}

/// Writes the notice to its own file under reports/ and adds it to the inbox.
pub fn keep(state_dir: &Path, notice: &Notice, now: Timestamp) -> Result<InboxEntry> {
    let at = iso(now);
    // `YYYY-MM-DD-<HHMMSSmmm>-<event>[-<slug of key>].md`
    let time: String = at[11..23].chars().filter(char::is_ascii_digit).collect();
    let key = notice.key.as_deref().filter(|k| !k.is_empty()).map(|k| format!("-{}", slug(k))).unwrap_or_default();
    let file = state_dir.join("reports").join(format!("{}-{time}-{}{key}.md", &at[..10], notice.event.as_str()));
    let body = if notice.text.is_empty() { String::new() } else { format!("{}\n", notice.text) };
    let report = notice.report_path.as_deref().filter(|p| !p.is_empty()).map(|p| format!("\nReport: {p}\n")).unwrap_or_default();
    write_file_atomic(&file, &format!("# {}\n\n{body}{report}", notice.title))?;
    let entry = InboxEntry { at, event: notice.event.as_str().to_string(), title: notice.title.clone(), file: file.to_string_lossy().into_owned() };
    let path = state_dir.join("inbox.jsonl");
    let mut line = serde_json::to_string(&entry)?;
    line.push('\n');
    OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut f| f.write_all(line.as_bytes()))
        .with_context(|| format!("append {}", path.display()))?;
    Ok(entry)
}

/// Entries the agent hasn't read yet (all of them with `all`).
pub fn unread(state_dir: &Path, all: bool) -> Result<Vec<InboxEntry>> {
    let path = state_dir.join("inbox.jsonl");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let read_until = read_state::<ReadMark>(state_dir, "inbox-read.json").unwrap_or_default().read_until;
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    Ok(text
        .split('\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_str::<InboxEntry>(line).ok())
        .filter(|e| all || read_until.as_deref().is_none_or(|until| e.at.as_str() > until))
        .collect())
}

/// Marks everything kept up to `until` (an ISO time, as in `InboxEntry::at`) as read.
pub fn mark_read(state_dir: &Path, until: &str) -> Result<()> {
    write_state(state_dir, "inbox-read.json", &ReadMark { read_until: Some(until.to_string()) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NotifyEvent;
    use crate::notify::Notice;
    use crate::util::parse_time;

    #[test]
    fn keep_then_unread_then_mark_read_then_unread_is_empty_and_all_returns_everything() {
        let dir = std::env::temp_dir().join(format!("cvecondor-inbox-{}-{}", std::process::id(), iso(crate::util::now()).replace([':', '.'], "")));
        let at = |s: &str| parse_time(s).expect("a valid time");
        let notice = |event, key: Option<&str>| Notice {
            event,
            title: "act today: acme/api".to_string(),
            text: "details".to_string(),
            key: key.map(str::to_string),
            severity: None,
            urls: None,
            report_path: Some("/r.md".to_string()),
        };

        let first = keep(&dir, &notice(NotifyEvent::Urgent, Some("CVE-2026-1/x")), at("2026-10-21T06:00:01.234Z")).expect("keeps");
        assert!(first.file.ends_with("/reports/2026-10-21-060001234-urgent-cve-2026-1-x.md"), "{}", first.file);
        assert_eq!(fs::read_to_string(&first.file).expect("the notice file"), "# act today: acme/api\n\ndetails\n\nReport: /r.md\n");
        assert_eq!(unread(&dir, false).expect("reads"), std::slice::from_ref(&first));

        mark_read(&dir, &first.at).expect("marks");
        assert!(unread(&dir, false).expect("reads").is_empty());
        let second = keep(&dir, &notice(NotifyEvent::Case, None), at("2026-10-21T07:00:00.000Z")).expect("keeps");
        assert_eq!(unread(&dir, false).expect("reads"), std::slice::from_ref(&second));
        assert_eq!(unread(&dir, true).expect("reads"), [first, second]);

        let _ = fs::remove_dir_all(&dir);
    }
}
