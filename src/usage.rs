// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! How many tokens the user's agent CLI used for CVECondor's runs: read out of the CLI's own structured output,
//! never invented. Every number is optional, and absent means unknown, never 0. A CLI whose output is not read (a
//! custom command, omp), or whose output does not parse in the declared format, leaves the run's usage unknown;
//! nothing here can fail a run or change its outcome.
//!
//! `input` counts every input token the CLI sent, cached or not, and `cache_read` and `cache_write` are the parts of it
//! read from and written to the prompt cache, so runs of different CLIs add up. Claude Code reports its cache
//! tokens next to its input, so they are added to it; Codex's `input_tokens` is taken as it reports it, and is *assumed*
//! to include its cached tokens (not stated in its docs or event structs). The cost is the CLI's own client-side
//! estimate at list prices, not what a subscription charges.
//!
//! Counted: responder runs and the Telegram relay. Not counted yet: `cvecondor follow` sessions, omp,
//! classifier.dev, and money budgets.
//!
//! One line per run is appended to `usage.jsonl` in the state dir: counts and names only, never a prompt, a text or a
//! reply. Lines older than 90 days are dropped whenever one is appended.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::state::write_file_atomic;
use crate::util::{iso, parse_time};

/// The state file: one JSON line per run.
pub const FILE: &str = "usage.jsonl";

/// Lines older than this are dropped when one is appended.
pub const KEEP_DAYS: i64 = 90;

/// What `status` totals.
pub const STATUS_DAYS: i64 = 7;

/// Where the preset for Codex has it write its last message (`-o {workdir}/last-message.md`).
pub const CODEX_LAST_MESSAGE: &str = "last-message.md";

/// What a run's stdout is read as (`responder.usage`), and in a record, where its numbers came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Format {
    /// One JSON object (`claude -p --output-format json`).
    #[serde(rename = "claude-json")]
    ClaudeJson,
    /// JSON lines (`codex exec --json`).
    #[serde(rename = "codex-jsonl")]
    CodexJsonl,
    /// Not read: stdout is the answer as it is, the usage unknown. In a record: `unknown`.
    #[default]
    #[serde(rename = "unknown")]
    None,
}

impl Format {
    pub const NAMES: &'static str = "claude-json, codex-jsonl, none";

    /// The `responder.usage` value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeJson => "claude-json",
            Self::CodexJsonl => "codex-jsonl",
            Self::None => "none",
        }
    }

    /// A `responder.usage` value.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "claude-json" => Some(Self::ClaudeJson),
            "codex-jsonl" => Some(Self::CodexJsonl),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// What one run used. Absent is unknown, never 0.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Usage {
    pub source: Format,
    /// Every input token, cached or not (see the module doc).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<u64>,
    /// Of `input`: read from the prompt cache.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_read: Option<u64>,
    /// Of `input`: written to the prompt cache.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_write: Option<u64>,
    /// Reasoning tokens, as the CLI reports them (Codex only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<u64>,
    /// The CLI's own estimate in US dollars, at list prices: not a bill.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<String>,
    /// Whether the numbers include the subagents the agent started: `None`, unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subagents: Option<bool>,
}

impl Usage {
    /// Whether any count or cost is known.
    pub fn is_known(&self) -> bool {
        [self.input, self.output, self.cache_read, self.cache_write, self.reasoning].iter().any(Option::is_some) || self.cost_usd.is_some()
    }
}

/// A run's stdout read as its format says.
#[derive(Debug, Clone, PartialEq)]
pub struct Unwrapped {
    /// The answer text: what stdout was before usage was asked for. The raw stdout when it did not parse.
    pub text: String,
    pub usage: Usage,
}

/// Reads `stdout` as `format`. `workdir` is where Codex's `-o` file is. Never fails: what does not parse keeps the
/// raw stdout as the text and leaves the usage unknown.
pub fn unwrap(format: Format, stdout: &str, workdir: &Path) -> Unwrapped {
    let parsed = match format {
        Format::ClaudeJson => parse_claude(stdout),
        Format::CodexJsonl => {
            let file = fs::read_to_string(workdir.join(CODEX_LAST_MESSAGE)).ok().filter(|t| !t.trim().is_empty());
            parse_codex(stdout, file.as_deref())
        }
        Format::None => None,
    };
    match parsed {
        Some((text, usage)) if usage.is_known() => Unwrapped { text, usage },
        // An answer was read but no count: the text is unwrapped all the same.
        Some((text, _)) => Unwrapped { text, usage: Usage::default() },
        None => Unwrapped { text: stdout.to_string(), usage: Usage::default() },
    }
}

fn count(v: Option<&Value>) -> Option<u64> {
    let v = v?;
    v.as_u64().or_else(|| v.as_f64().filter(|f| *f >= 0.0 && f.fract() == 0.0).map(|f| f as u64))
}

/// Adds `n` to a total that stays unknown until one number is known.
fn add(total: &mut Option<u64>, n: Option<u64>) {
    if let Some(n) = n {
        *total = Some(total.unwrap_or(0).saturating_add(n));
    }
}

/// `claude -p --output-format json`: one object, `type` `result`. The answer is `.result`; the counts are summed over
/// `modelUsage`, which, unlike `.usage`, includes subagents and side calls.
pub fn parse_claude(stdout: &str) -> Option<(String, Usage)> {
    let v: Value = serde_json::from_str(stdout.trim()).ok()?;
    if v.get("type")?.as_str()? != "result" {
        return None;
    }
    // An error result without text has none: the answer is empty, as a CLI that printed nothing.
    let text = v.get("result").and_then(Value::as_str).unwrap_or_default().to_string();
    let mut usage = Usage { source: Format::ClaudeJson, subagents: Some(true), ..Usage::default() };
    let mut cost: Option<f64> = None;
    if let Some(models) = v.get("modelUsage").and_then(Value::as_object) {
        for (name, m) in models {
            usage.models.push(name.clone());
            let (fresh, read, write) = (count(m.get("inputTokens")), count(m.get("cacheReadInputTokens")), count(m.get("cacheCreationInputTokens")));
            for part in [fresh, read, write] {
                add(&mut usage.input, part);
            }
            add(&mut usage.cache_read, read);
            add(&mut usage.cache_write, write);
            add(&mut usage.output, count(m.get("outputTokens")));
            if let Some(c) = m.get("costUSD").and_then(Value::as_f64) {
                cost = Some(cost.unwrap_or(0.0) + c);
            }
        }
    }
    usage.cost_usd = v.get("total_cost_usd").and_then(Value::as_f64).or(cost);
    Some((text, usage))
}

/// `codex exec --json`: one event per line (other lines are ignored). The counts are summed over `turn.completed`.
/// The answer is the `-o` file (`last_message`), else the last `agent_message`, else what `turn.failed` and `error`
/// said, so a limit message still reaches the retry queue.
pub fn parse_codex(stdout: &str, last_message: Option<&str>) -> Option<(String, Usage)> {
    let events: Vec<Value> = stdout.lines().filter_map(|l| serde_json::from_str::<Value>(l.trim()).ok()).filter(is_codex_event).collect();
    if events.is_empty() {
        return None;
    }
    let mut usage = Usage { source: Format::CodexJsonl, ..Usage::default() };
    let (mut message, mut errors) = (None, Vec::<String>::new());
    for event in &events {
        match event["type"].as_str().unwrap_or_default() {
            "turn.completed" => {
                let u = &event["usage"];
                add(&mut usage.input, count(u.get("input_tokens")));
                add(&mut usage.cache_read, count(u.get("cached_input_tokens")));
                add(&mut usage.cache_write, count(u.get("cache_write_input_tokens")));
                add(&mut usage.output, count(u.get("output_tokens")));
                add(&mut usage.reasoning, count(u.get("reasoning_output_tokens")));
            }
            "item.completed" if event.pointer("/item/type").and_then(Value::as_str) == Some("agent_message") => {
                if let Some(text) = event.pointer("/item/text").and_then(Value::as_str) {
                    message = Some(text.to_string());
                }
            }
            "turn.failed" | "error" => {
                if let Some(text) = event.pointer("/error/message").or_else(|| event.get("message")).and_then(Value::as_str)
                    && !errors.iter().any(|e| e == text)
                {
                    errors.push(text.to_string());
                }
            }
            _ => {}
        }
    }
    let text = last_message.map(str::to_string).or(message).unwrap_or_else(|| errors.join("\n"));
    Some((text, usage))
}

/// A line that is one of Codex's events (`thread.*`, `turn.*`, `item.*`, `error`), not some other JSON.
fn is_codex_event(v: &Value) -> bool {
    v.get("type").and_then(Value::as_str).is_some_and(|t| t == "error" || ["thread.", "turn.", "item."].iter().any(|p| t.starts_with(p)))
}

/// Which part of CVECondor ran the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Component {
    Responder,
    Relay,
}

/// One line of `usage.jsonl`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    /// When the run ended (ISO 8601).
    pub at: String,
    pub component: Component,
    /// The case key (responder runs only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The preset's name, else the command's program.
    pub cli: String,
    pub mode: String,
    pub usage: Usage,
}

/// Serialises appends within the process (a responder runs on its own thread, the relay on another).
static WRITE: Mutex<()> = Mutex::new(());

fn cutoff(now: Timestamp, days: i64) -> Option<Timestamp> {
    now.checked_sub(SignedDuration::from_hours(24 * days)).ok()
}

/// Appends one record, first dropping the lines older than `KEEP_DAYS` (a line that does not parse goes too).
pub fn append(dir: &Path, record: &Record, now: Timestamp) -> anyhow::Result<()> {
    let _guard = WRITE.lock().unwrap_or_else(PoisonError::into_inner);
    let file = dir.join(FILE);
    let limit = cutoff(now, KEEP_DAYS);
    let fresh = |line: &str| match (serde_json::from_str::<Record>(line).ok().and_then(|r| parse_time(&r.at)), limit) {
        (Some(at), Some(limit)) => at >= limit,
        (Some(_), None) => true,
        (None, _) => false,
    };
    // Only the first line is looked at to know whether anything is due to go: the file is in time order.
    let first = fs::File::open(&file).ok().and_then(|f| BufReader::new(f).lines().next()?.ok());
    if first.is_some_and(|line| !fresh(&line)) {
        let kept: String = fs::read_to_string(&file).unwrap_or_default().lines().filter(|l| fresh(l)).map(|l| format!("{l}\n")).collect();
        write_file_atomic(&file, &kept)?;
    }
    let mut line = serde_json::to_string(record)?;
    line.push('\n');
    let mut f = fs::OpenOptions::new().create(true).append(true).mode(0o600).open(&file)?;
    f.write_all(line.as_bytes())?;
    Ok(())
}

/// Records one run; a failure is logged and never fails the run.
pub fn note(dir: &Path, component: Component, key: Option<&str>, cli: &str, mode: &str, usage: Usage) {
    let now = crate::util::now();
    let record = Record { at: iso(now), component, key: key.map(str::to_string), cli: cli.to_string(), mode: mode.to_string(), usage };
    if let Err(e) = append(dir, &record, now) {
        crate::util::log(&format!("usage: {e:#}"));
    }
}

/// Every readable record; a line that does not parse is skipped.
pub fn read(dir: &Path) -> Vec<Record> {
    fs::read_to_string(dir.join(FILE)).unwrap_or_default().lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}

/// `1.2M`, `40k`, `950`.
pub fn compact(n: u64) -> String {
    let trim = |s: String| s.replace(".0", "");
    if n < 1000 {
        n.to_string()
    } else if n < 999_500 {
        let k = n as f64 / 1000.0;
        if k < 9.95 { trim(format!("{k:.1}k")) } else { format!("{k:.0}k") }
    } else {
        trim(format!("{:.1}M", n as f64 / 1_000_000.0))
    }
}

fn runs(n: usize) -> String {
    format!("{n} run{}", if n == 1 { "" } else { "s" })
}

/// The `status` line over the last `STATUS_DAYS`, or `None` when no run is recorded in them:
/// `Agent usage, last 7 days: responder 4 runs, relay 2 runs: 1.2M input (900k cached), 40k output tokens, ~$3.10 estimated; 1 run unknown.`
/// Totals add up the runs whose counts are known; a run with none is counted as unknown, not as 0.
pub fn status_line(dir: &Path, now: Timestamp) -> Option<String> {
    let limit = cutoff(now, STATUS_DAYS);
    let records: Vec<Record> = read(dir).into_iter().filter(|r| parse_time(&r.at).is_some_and(|at| limit.is_none_or(|l| at >= l))).collect();
    if records.is_empty() {
        return None;
    }
    let by = |c: Component| records.iter().filter(|r| r.component == c).count();
    let who: Vec<String> = [(Component::Responder, "responder"), (Component::Relay, "relay")]
        .into_iter()
        .filter(|(c, _)| by(*c) > 0)
        .map(|(c, name)| format!("{name} {}", runs(by(c))))
        .collect();
    let known: Vec<&Usage> = records.iter().map(|r| &r.usage).filter(|u| u.is_known()).collect();
    let unknown = records.len() - known.len();
    let total = |f: fn(&Usage) -> Option<u64>| {
        let mut sum = None;
        for u in &known {
            add(&mut sum, f(u));
        }
        sum
    };
    let mut parts = Vec::new();
    if let Some(input) = total(|u| u.input) {
        parts.push(match total(|u| u.cache_read) {
            Some(cached) => format!("{} input ({} cached)", compact(input), compact(cached)),
            None => format!("{} input", compact(input)),
        });
    }
    if let Some(output) = total(|u| u.output) {
        parts.push(format!("{} output", compact(output)));
    }
    let mut tokens = parts.join(", ");
    if !tokens.is_empty() {
        tokens.push_str(" tokens");
    }
    let cost: Option<f64> = known.iter().filter_map(|u| u.cost_usd).fold(None, |t, c| Some(t.unwrap_or(0.0) + c));
    let mut figures: Vec<String> = Vec::new();
    if !tokens.is_empty() {
        figures.push(tokens);
    }
    if let Some(c) = cost {
        figures.push(format!("~${c:.*} estimated", if c < 0.01 && c > 0.0 { 3 } else { 2 }));
    }
    let tail = match (figures.is_empty(), unknown) {
        (true, _) => "unknown".to_string(),
        (false, 0) => figures.join(", "),
        (false, n) => format!("{}; {} unknown", figures.join(", "), runs(n)),
    };
    Some(format!("Agent usage, last {STATUS_DAYS} days: {}: {tail}.", who.join(", ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLAUDE: &str = include_str!("../tests/fixtures/usage/claude-json.json");
    // Synthetic: built from codex-rs/exec/src/exec_events.rs, not recorded from a run.
    const CODEX: &str = include_str!("../tests/fixtures/usage/codex-exec-json.synthetic.jsonl");
    const CODEX_FAILED: &str = include_str!("../tests/fixtures/usage/codex-failed.jsonl");

    #[test]
    fn claude_json_gives_the_answer_and_sums_model_usage_not_the_main_loop() {
        let (text, usage) = parse_claude(CLAUDE).expect("parses");
        assert_eq!(text, "OK");
        assert_eq!(usage.source, Format::ClaudeJson);
        // `usage.input_tokens` is 2 (main loop only); the model line also counts side calls and subagents.
        assert_eq!((usage.input, usage.cache_read, usage.cache_write, usage.output), (Some(1176 + 21770 + 16212), Some(21770), Some(16212), Some(20)));
        assert_eq!((usage.cost_usd, usage.models.as_slice(), usage.subagents), (Some(0.0035877), ["claude-haiku-5-5".to_string()].as_slice(), Some(true)));
        assert_eq!(usage.reasoning, None, "not reported is unknown, not 0");
    }

    #[test]
    fn codex_jsonl_sums_turns_and_takes_the_answer_from_the_file_else_the_last_message() {
        let (text, usage) = parse_codex(CODEX, None).expect("parses");
        assert_eq!(text, "Second answer.");
        assert_eq!(usage.source, Format::CodexJsonl);
        assert_eq!((usage.input, usage.cache_read, usage.cache_write, usage.output, usage.reasoning), (Some(1500), Some(1000), Some(40), Some(60), Some(25)));
        assert_eq!((usage.cost_usd, usage.subagents, usage.models.is_empty()), (None, None, true), "Codex reports no cost, model or subagent scope");
        assert_eq!(parse_codex(CODEX, Some("From the file.\n")).expect("parses").0, "From the file.\n");
    }

    #[test]
    fn a_failed_codex_run_has_no_counts_and_its_errors_are_the_text() {
        let (text, usage) = parse_codex(CODEX_FAILED, None).expect("parses");
        assert!(!usage.is_known());
        assert!(text.contains("model_not_found") && !text.contains("Model metadata"), "{text}");
        assert_eq!(text.lines().count(), 1, "the same message from `error` and `turn.failed` is said once");
    }

    #[test]
    fn what_does_not_parse_keeps_the_raw_stdout_and_leaves_usage_unknown() {
        let dir = Path::new("/nonexistent");
        for (format, stdout) in [
            (Format::ClaudeJson, "garbage"),
            (Format::ClaudeJson, ""),
            (Format::ClaudeJson, "{\"type\":\"assistant\"}"),
            (Format::ClaudeJson, "[1,2]"),
            (Format::CodexJsonl, "garbage\nmore"),
            (Format::CodexJsonl, ""),
            (Format::CodexJsonl, CLAUDE),
            (Format::None, CLAUDE),
        ] {
            let got = unwrap(format, stdout, dir);
            assert_eq!((got.text.as_str(), got.usage.clone()), (stdout, Usage::default()), "{format:?} {stdout:?}");
        }
        assert_eq!(unwrap(Format::ClaudeJson, CLAUDE, dir).text, "OK");
        // Unknown fields, wrong types and a missing `modelUsage` are not errors; the text is still unwrapped.
        let odd = unwrap(Format::ClaudeJson, r#"{"type":"result","result":"Done","modelUsage":{"m":{"inputTokens":"many"}},"surprise":[1]}"#, dir);
        assert_eq!((odd.text.as_str(), odd.usage.is_known()), ("Done", false));
        let bare = unwrap(Format::ClaudeJson, r#"{"type":"result","subtype":"error_max_turns","is_error":true}"#, dir);
        assert_eq!((bare.text.as_str(), bare.usage), ("", Usage::default()));
    }

    #[test]
    fn the_codex_file_in_the_workdir_is_the_answer() {
        let dir = std::env::temp_dir().join(format!("cvecondor-usage-file-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("creates");
        fs::write(dir.join(CODEX_LAST_MESSAGE), "Final text.").expect("writes");
        let got = unwrap(Format::CodexJsonl, CODEX, &dir);
        assert_eq!((got.text.as_str(), got.usage.input), ("Final text.", Some(1500)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tokens_are_compact() {
        let shown: Vec<String> = [0, 950, 4200, 9_990, 10_400, 40_000, 999_400, 999_600, 1_200_000, 12_300_000].map(compact).into();
        assert_eq!(shown, ["0", "950", "4.2k", "10k", "10k", "40k", "999k", "1M", "1.2M", "12.3M"]);
    }

    fn record(at: &str, component: Component, usage: Usage) -> Record {
        Record { at: at.to_string(), component, key: Some("CVE-1".into()), cli: "claude".into(), mode: "act".into(), usage }
    }

    fn known(input: u64, cached: u64, output: u64, cost: Option<f64>) -> Usage {
        Usage { source: Format::ClaudeJson, input: Some(input), cache_read: Some(cached), output: Some(output), cost_usd: cost, ..Usage::default() }
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("cvecondor-usage-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("creates");
        dir
    }

    #[test]
    fn the_status_line_adds_known_runs_and_counts_unknown_ones_apart() {
        let dir = scratch("status");
        let now: Timestamp = "2026-11-12T12:00:00Z".parse().expect("valid");
        assert_eq!(status_line(&dir, now), None, "no records, no line");
        let rows = [
            ("2026-11-12T10:00:00Z", Component::Responder, known(900_000, 700_000, 30_000, Some(2.5))),
            ("2026-11-11T10:00:00Z", Component::Responder, known(300_000, 200_000, 10_000, Some(0.6))),
            ("2026-11-10T10:00:00Z", Component::Relay, Usage::default()),
            ("2026-11-08T10:00:00Z", Component::Relay, known(1, 0, 1, None)),
            ("2026-10-30T10:00:00Z", Component::Responder, known(5_000_000, 0, 5_000_000, Some(99.0))),
        ];
        for (at, component, usage) in rows {
            append(&dir, &record(at, component, usage), now).expect("appends");
        }
        assert_eq!(
            status_line(&dir, now).expect("a line"),
            "Agent usage, last 7 days: responder 2 runs, relay 2 runs: 1.2M input (900k cached), 40k output tokens, ~$3.10 estimated; 1 run unknown."
        );
        let only_unknown = scratch("status-unknown");
        append(&only_unknown, &record("2026-11-12T10:00:00Z", Component::Relay, Usage::default()), now).expect("appends");
        assert_eq!(status_line(&only_unknown, now).expect("a line"), "Agent usage, last 7 days: relay 1 run: unknown.");
        for d in [dir, only_unknown] {
            let _ = fs::remove_dir_all(d);
        }
    }

    #[test]
    fn lines_older_than_90_days_go_when_one_is_appended_and_the_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("prune");
        let old: Timestamp = "2026-07-01T00:00:00Z".parse().expect("valid");
        append(&dir, &record("2026-07-01T00:00:00.000Z", Component::Responder, known(1, 0, 1, None)), old).expect("appends");
        append(&dir, &record("2026-10-01T00:00:00.000Z", Component::Responder, known(2, 0, 2, None)), old).expect("appends");
        // 2026-07-01 is 134 days before 2026-11-12, 2026-10-01 is 42.
        let now: Timestamp = "2026-11-12T00:00:00Z".parse().expect("valid");
        append(&dir, &record("2026-11-12T00:00:00.000Z", Component::Relay, known(3, 0, 3, None)), now).expect("appends");
        let inputs: Vec<Option<u64>> = read(&dir).iter().map(|r| r.usage.input).collect();
        assert_eq!(inputs, [Some(2), Some(3)]);
        assert_eq!(fs::metadata(dir.join(FILE)).expect("exists").permissions().mode() & 0o777, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }
}
