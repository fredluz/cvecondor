// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! The retry queue: a responder run that did not finish is never dropped. Its case waits here, with why, until
//! the agent's own reset time when it named one, else after a backoff that doubles up to a cap. The cycle drains the
//! queue within `maxPerCycle`, most urgent first, so a reset does not fire every waiting case at once. A cause that
//! will not fix itself (the same error again and again, or a limit days away) is said once, as an urgent line.

use std::path::Path;
use std::sync::LazyLock;

use anyhow::Result;
use indexmap::IndexMap;
use jiff::civil::{Date, DateTime, Weekday};
use jiff::tz::TimeZone;
use jiff::{SignedDuration, Timestamp, ToSpan};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::config::NotifyEvent;
use crate::notify::Notice;
use crate::state::{read_state, write_state};
use crate::util::{iso, parse_time};
use crate::watch::{Case, ResponseRecord, ResponseState};

/// `retries.json` in the state dir.
const FILE: &str = "retries.json";

/// The first backoff; each further failure doubles it.
const BACKOFF_FIRST_MS: i64 = 5 * 60_000;
/// The longest backoff.
const BACKOFF_CAP_MS: i64 = 3 * 3_600_000;
/// A run may start this long after the agent's named reset, not on the second.
const AFTER_RESET_MS: i64 = 60_000;
/// The same failure this many times in a row is one that will not fix itself.
pub const STUCK_AFTER: u32 = 3;
/// A limit that resets further away than this will not clear on its own soon enough either.
const LIMIT_LONG_MS: i64 = 6 * 3_600_000;

/// One case waiting for another run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub key: String,
    /// Why the last run did not finish (redacted, one line).
    pub reason: String,
    /// Failed runs since the case last finished one.
    pub attempts: u32,
    /// Failed runs in a row with this reason.
    pub streak: u32,
    /// The agent's usage limit, not an error of its own.
    pub limit: bool,
    pub first_failed_at: String,
    pub failed_at: String,
    /// Not before this.
    pub next_at: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Queue {
    #[serde(default)]
    pub entries: IndexMap<String, Entry>,
    /// The agent said it is out of quota until then: nothing is started before it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused_until: Option<String>,
    /// The reason last said urgently that the responder can't run, so it is said once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_told: Option<String>,
    /// Per case, `startedAt` of the last failed response run counted: a record is counted once, even after its
    /// case left the queue (a newer event replaced the retry) while the record still stands.
    #[serde(default)]
    pub counted: IndexMap<String, String>,
}

pub fn read(dir: &Path) -> Queue {
    read_state(dir, FILE).unwrap_or_default()
}

pub fn write(dir: &Path, queue: &Queue) -> Result<()> {
    write_state(dir, FILE, queue)
}

/// What a run that did not finish costs in time: 5 minutes, doubling per failure, at most 3 hours.
pub fn backoff_ms(attempts: u32) -> i64 {
    let doublings = attempts.saturating_sub(1).min(20);
    (BACKOFF_FIRST_MS << doublings).min(BACKOFF_CAP_MS)
}

fn at(ms: i64) -> Timestamp {
    Timestamp::from_millisecond(ms).unwrap_or(Timestamp::MAX)
}

fn when(s: &Option<String>) -> Option<Timestamp> {
    s.as_deref().and_then(parse_time)
}

/// The agent says it is out of quota (Claude: "You've hit your session limit", codex: "usage limit", an API's 429).
pub fn is_limit(text: &str) -> bool {
    static LIMIT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\b(usage|session|rate|weekly|daily|monthly|5-hour|token|credit)s?[ -]limit|hit your [a-z ]*limit|limit (reached|exceeded|hit)|quota|too many requests|rate.?limited|\b429\b")
            .expect("valid regex")
    });
    LIMIT.is_match(text)
}

/// When the agent says its limit resets, as it prints it: `resets 7:40pm (UTC)`, `resets Oct 29, 2pm (Europe/London)`,
/// `try again at 3:42 PM`, `try again in 2h 31m`, `retry after 90 seconds`, `usage limit reached|1761170400`.
/// A time of day with no date is the next one after `reference` (the moment the run failed), in the zone it names
/// (UTC without one).
pub fn parse_reset(text: &str, reference: Timestamp) -> Option<Timestamp> {
    static EPOCH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)limit reached\|(\d{10})\b").expect("valid regex"));
    static KEYWORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(?:resets?(?:\s+at)?|(?:try|retry)(?:\s+again)?\s+at|available again at)\s+([^\n]{1,60})").expect("valid regex"));
    static RELATIVE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\b(?:(?:try|retry)(?:\s+again)?|resets?|available again)\s+(?:in|after)\s+((?:\d+\s*(?:days?|d|hours?|hrs?|h|minutes?|mins?|m|seconds?|secs?|s)\b[\s,]*(?:and\s+)?)+)")
            .expect("valid regex")
    });
    static UNIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(\d+)\s*(days?|d|hours?|hrs?|h|minutes?|mins?|m|seconds?|secs?|s)\b").expect("valid regex"));
    static CLOCK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(\d{1,2})(?::(\d{2}))?\s*([ap])\.?m\b|\b(\d{1,2}):(\d{2})\b").expect("valid regex"));
    static ZONE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\(([A-Za-z][A-Za-z0-9_/+\-]*)\)").expect("valid regex"));
    static DAY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+(\d{1,2})\b").expect("valid regex"));
    static WEEKDAY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(mon|tue|wed|thu|fri|sat|sun)[a-z]*\b").expect("valid regex"));

    if let Some(m) = EPOCH.captures(text) {
        return Timestamp::from_second(m[1].parse().ok()?).ok();
    }
    if let Some(m) = RELATIVE.captures(text) {
        let mut seconds = 0i64;
        for part in UNIT.captures_iter(&m[1]) {
            let n: i64 = part[1].parse().ok()?;
            seconds += n * match part[2].to_lowercase().chars().next()? {
                'd' => 86_400,
                'h' => 3_600,
                'm' => 60,
                _ => 1,
            };
        }
        return reference.checked_add(SignedDuration::from_secs(seconds)).ok();
    }
    let rest = KEYWORD.captures(text)?.get(1)?.as_str();
    let clock = CLOCK.captures(rest)?;
    let (hour, minute) = match (clock.get(1), clock.get(4)) {
        (Some(h), _) => {
            let h: i8 = h.as_str().parse().ok()?;
            let pm = clock[3].eq_ignore_ascii_case("p");
            if !(1..=12).contains(&h) {
                return None;
            }
            ((h % 12) + if pm { 12 } else { 0 }, clock.get(2).map_or(Some(0), |m| m.as_str().parse().ok())?)
        }
        (None, _) => (clock[4].parse().ok()?, clock[5].parse().ok()?),
    };
    let zone = ZONE.captures(rest).and_then(|z| TimeZone::get(&z[1]).ok()).unwrap_or(TimeZone::UTC);
    let today = zone.to_datetime(reference).date();
    let on = |date: Date| DateTime::from_parts(date, jiff::civil::time(hour, minute, 0, 0)).to_zoned(zone.clone()).ok().map(|z| z.timestamp());
    if let Some(d) = DAY.captures(rest) {
        let month = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"].iter().position(|m| d[1].eq_ignore_ascii_case(m))? as i8 + 1;
        let day: i8 = d[2].parse().ok()?;
        let this_year = on(Date::new(today.year(), month, day).ok()?)?;
        return if this_year >= reference { Some(this_year) } else { on(Date::new(today.year() + 1, month, day).ok()?) };
    }
    if let Some(w) = WEEKDAY.captures(rest) {
        let target = match w[1].to_lowercase().as_str() {
            "mon" => Weekday::Monday,
            "tue" => Weekday::Tuesday,
            "wed" => Weekday::Wednesday,
            "thu" => Weekday::Thursday,
            "fri" => Weekday::Friday,
            "sat" => Weekday::Saturday,
            _ => Weekday::Sunday,
        };
        for ahead in 0..=7 {
            let candidate = on(today.checked_add(ahead.days()).ok()?)?;
            if today.checked_add(ahead.days()).ok()?.weekday() == target && candidate > reference {
                return Some(candidate);
            }
        }
        return None;
    }
    let candidate = on(today)?;
    if candidate > reference { Some(candidate) } else { on(today.checked_add(1.day()).ok()?) }
}

impl Queue {
    /// The agent is out of quota for now.
    pub fn paused(&self, now: Timestamp) -> bool {
        when(&self.paused_until).is_some_and(|until| until > now)
    }

    /// Records a run that did not finish. Returns true when the case was not queued before.
    pub fn fail(&mut self, key: &str, reason: &str, failed_at: Timestamp, now: Timestamp) -> bool {
        let before = self.entries.get(key);
        let reason = reason.split('\n').next().unwrap_or_default().trim().to_string();
        let (attempts, streak) = match before {
            Some(e) => (e.attempts + 1, if e.reason == reason { e.streak + 1 } else { 1 }),
            None => (1, 1),
        };
        let limit = is_limit(&reason);
        let after = failed_at.as_millisecond().max(now.as_millisecond());
        let reset = parse_reset(&reason, failed_at).map(|t| t.as_millisecond() + AFTER_RESET_MS);
        let next = reset.filter(|_| limit).unwrap_or(after + backoff_ms(attempts));
        // The reset time of an earlier run is not later than a new one's: a run that fails again names its own.
        if limit && at(next) > now {
            let held = when(&self.paused_until).map_or(0, |t| t.as_millisecond());
            self.paused_until = Some(iso(at(next.max(held))));
        }
        let entry = Entry {
            key: key.to_string(),
            reason,
            attempts,
            streak,
            limit,
            first_failed_at: before.map_or_else(|| iso(failed_at), |e| e.first_failed_at.clone()),
            failed_at: iso(failed_at),
            next_at: iso(at(next)),
        };
        self.entries.insert(key.to_string(), entry).is_none()
    }

    /// A run finished: the case leaves the queue, and an earlier "can't run" is over.
    pub fn done(&mut self, key: &str) {
        if self.entries.shift_remove(key).is_some() {
            self.blocked_told = None;
            let paused = self.entries.values().filter(|e| e.limit).filter_map(|e| parse_time(&e.next_at)).max();
            self.paused_until = paused.map(iso);
        }
    }

    /// A retry of the case started: not again before the next backoff, whatever it does (its record says).
    pub fn started(&mut self, key: &str, now: Timestamp) {
        if let Some(e) = self.entries.get_mut(key) {
            e.next_at = iso(at(now.as_millisecond() + backoff_ms(e.attempts + 1)));
        }
    }

    /// A run for the case is about to start: it replaces the queued one.
    pub fn replace(&mut self, key: &str) {
        self.entries.shift_remove(key);
    }

    /// The entry that can't be expected to fix itself and has not been said yet: it fails the same way again and
    /// again, or the agent's limit resets too far away. Marks it said.
    pub fn stuck(&mut self, now: Timestamp) -> Option<Entry> {
        let entry = self
            .entries
            .values()
            .find(|e| {
                self.blocked_told.as_deref() != Some(e.reason.as_str())
                    && ((!e.limit && e.streak >= STUCK_AFTER) || (e.limit && parse_time(&e.next_at).is_some_and(|t| t.as_millisecond() - now.as_millisecond() > LIMIT_LONG_MS)))
            })
            .cloned()?;
        self.blocked_told = Some(entry.reason.clone());
        Some(entry)
    }

    /// The keys whose run can start now, in no particular order.
    pub fn due(&self, now: Timestamp) -> Vec<&Entry> {
        if self.paused(now) {
            return Vec::new();
        }
        self.entries.values().filter(|e| parse_time(&e.next_at).is_some_and(|t| t <= now)).collect()
    }
}

/// Why a run did not finish, in one line: how it ended and the agent's own words about it (its limit message, "not
/// logged in", the shell's "command not found"), which the queue reads the reset time from.
pub fn failure_reason(how: &str, stdout: &str, stderr: &str) -> String {
    static WORDS: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)login|log in|logged|auth|credential|token|api key|expired|unauthori[sz]ed|forbidden|denied|not found|error|fail").expect("valid regex"));
    // A long stdout is a report, not an error message (and may talk about rate limits for a living).
    let stdout = if stdout.len() > 1000 { "" } else { stdout };
    let lines: Vec<&str> = stdout.lines().chain(stderr.lines()).map(str::trim).filter(|l| !l.is_empty()).collect();
    let detail = lines.iter().find(|l| is_limit(l)).or_else(|| lines.iter().rev().find(|l| WORDS.is_match(l))).or_else(|| lines.last());
    match detail {
        Some(line) => format!("{how}: {}", line.split_whitespace().collect::<Vec<_>>().join(" ")),
        None => how.to_string(),
    }
}

/// What a cycle learned from the finished responses.
#[derive(Debug, Default)]
pub struct Absorbed {
    /// Cases that entered the queue now.
    pub queued: Vec<String>,
}

/// The first lines of the report of a run that left only an exit code behind (a record from before the queue):
/// where the agent's own words about its limit are.
fn report_head(record: &ResponseRecord) -> String {
    let Some(path) = record.report.as_deref() else { return String::new() };
    // A long report is the agent's work, not its error message.
    std::fs::read_to_string(path).ok().filter(|t| t.len() <= 1000).unwrap_or_default()
}

/// Folds finished responses into the queue: a failed run queues its case (or lengthens its wait), a finished one
/// takes it off. A record is counted once, so every failed record of an earlier version is picked up the first time.
pub fn absorb(queue: &mut Queue, records: &[ResponseRecord], cases: &indexmap::IndexMap<String, Case>, now: Timestamp) -> Absorbed {
    let mut out = Absorbed::default();
    queue.entries.retain(|key, _| cases.contains_key(key));
    queue.counted.retain(|key, _| cases.contains_key(key));
    for record in records {
        if !cases.contains_key(&record.key) {
            continue;
        }
        match record.state {
            ResponseState::Running => {}
            ResponseState::Done => queue.done(&record.key),
            ResponseState::Failed => {
                if queue.counted.get(&record.key) == Some(&record.started_at) {
                    continue;
                }
                queue.counted.insert(record.key.clone(), record.started_at.clone());
                let error = record.error.clone().unwrap_or_else(|| "failed".to_string());
                // An error that is only an exit code: the agent's words are in its report.
                let reason = if error.contains(':') || error.chars().count() > 24 { error } else { format!("{error}: {}", report_head(record)) };
                let failed_at = when(&record.finished_at).unwrap_or(now);
                if queue.fail(&record.key, &reason, failed_at, now) {
                    out.queued.push(record.key.clone());
                }
            }
        }
    }
    out
}

/// One line for the inbox: what was queued and when it runs again.
pub fn queued_notice(queue: &Queue, cases: &indexmap::IndexMap<String, Case>, keys: &[String]) -> Notice {
    let mut lines = Vec::new();
    for key in keys {
        let (Some(entry), Some(case)) = (queue.entries.get(key), cases.get(key)) else { continue };
        lines.push(format!("- {key} {}: {}; next try {}", crate::watch::clip(&case.title, 100), entry.reason, entry.next_at));
    }
    let next = keys.iter().filter_map(|k| queue.entries.get(k)).map(|e| e.next_at.as_str()).min().unwrap_or_default();
    Notice {
        event: NotifyEvent::Report,
        title: format!("{} case(s) queued to retry: the responder did not finish; next try {next}", keys.len()),
        text: lines.join("\n"),
        key: None,
        severity: None,
        urls: None,
        report_path: None,
    }
}

/// The one urgent line for a cause that will not fix itself.
pub fn stuck_notice(entry: &Entry, waiting: usize) -> Notice {
    Notice {
        event: NotifyEvent::Urgent,
        title: format!("responder can't run: {} ({waiting} case(s) waiting; retrying, next try {})", crate::watch::clip(&entry.reason, 160), entry.next_at),
        text: String::new(),
        key: None,
        severity: None,
        urls: None,
        report_path: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> Timestamp {
        parse_time(s).expect("a time")
    }

    #[test]
    fn a_limit_message_names_its_reset_and_pauses_everything_until_then() {
        let failed = t("2026-10-22T17:30:00Z");
        let now = t("2026-10-22T17:31:00Z");
        let mut queue = Queue::default();
        assert!(queue.fail("A", "exit 1: You've hit your session limit · resets 7:40pm (UTC)", failed, now));
        let e = &queue.entries["A"];
        assert!(e.limit);
        assert_eq!(e.next_at, "2026-10-22T19:41:00.000Z", "the reset plus a minute");
        assert_eq!(queue.paused_until.as_deref(), Some("2026-10-22T19:41:00.000Z"));
        assert!(queue.due(t("2026-10-22T19:40:30Z")).is_empty(), "paused until the reset");
        assert_eq!(queue.due(t("2026-10-22T19:41:00Z")).len(), 1);

        // Other ways agents say it.
        assert_eq!(parse_reset("Usage limit reached. Try again at 3:42 PM.", failed), Some(t("2026-10-23T15:42:00Z")), "past today: tomorrow");
        assert_eq!(parse_reset("limit; resets Oct 29, 2pm (Europe/London)", failed), Some(t("2026-10-29T14:00:00Z")));
        assert_eq!(parse_reset("rate limited, try again in 2h 31m", failed), Some(t("2026-10-22T20:01:00Z")));
        assert_eq!(parse_reset("Claude AI usage limit reached|1761170400", failed), Some(t("2025-10-22T22:00:00Z")));
        assert_eq!(parse_reset("exit 1: segmentation fault", failed), None);
    }

    #[test]
    fn a_failure_with_no_reset_backs_off_by_doubling_to_a_cap() {
        let now = t("2026-10-22T10:00:00Z");
        let mut queue = Queue::default();
        let mut waits = Vec::new();
        for _ in 0..8 {
            queue.fail("A", "exit 1: boom", now, now);
            waits.push((t(&queue.entries["A"].next_at) - now).get_seconds() / 60);
        }
        assert_eq!(waits, [5, 10, 20, 40, 80, 160, 180, 180]);
        assert!(queue.paused_until.is_none(), "a plain error pauses only its own case");
    }

    #[test]
    fn a_cause_that_will_not_fix_itself_is_said_once() {
        let now = t("2026-10-22T10:00:00Z");
        let mut queue = Queue::default();
        for _ in 0..2 {
            queue.fail("A", "exit 1: Invalid API key · Please run /login", now, now);
        }
        assert!(queue.stuck(now).is_none(), "two are not yet a pattern");
        queue.fail("A", "exit 1: Invalid API key · Please run /login", now, now);
        assert!(queue.stuck(now).is_some());
        queue.fail("A", "exit 1: Invalid API key · Please run /login", now, now);
        queue.fail("B", "exit 1: Invalid API key · Please run /login", now, now);
        assert!(queue.stuck(now).is_none(), "not again on the next retry");
        queue.done("A");
        queue.fail("A", "exit 1: Invalid API key · Please run /login", now, now);
        queue.fail("A", "exit 1: Invalid API key · Please run /login", now, now);
        queue.fail("A", "exit 1: Invalid API key · Please run /login", now, now);
        assert!(queue.stuck(now).is_some(), "a new outage after a success is said again");
    }
}
