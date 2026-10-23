// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! The responder runs on the user's own agent CLI (Claude Code, Codex, omp, or
//! any command), logged in with their own subscription: no API key here. It gets
//! the standing brief and the case, works in a scratch directory, tells the user
//! what it is doing by dropping messages in `outbox/` (relayed by the watcher,
//! which alone holds the notification credentials), and leaves `report.md`.
//! It never inherits the watcher's credentials: every env var the config reads
//! is removed from its environment.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Result, anyhow};
use indexmap::{IndexMap, IndexSet};
use regex::Regex;

use crate::config::{Agent, Config, Env, Mode, NotifyEvent, SHIPPED_BRIEF_FILES, process_env, read_brief, redact, shipped_brief};
use crate::fixes::parse_waits;
use crate::name::{ENV_PREFIX, NAME};
use crate::notify::{Notice, Notifier};
use crate::state::{read_state, slug, write_file_atomic, write_state};
use crate::util::{self, iso};
use crate::watch::{Case, ResponseRecord, ResponseState, Triage, TriagePath, final_rating, read_responses};

/// Claude Code tools that keep a headless run open after its work is done (scheduled wake-ups, monitors, cron jobs).
const CLAUDE_NO_WAITS: &str = "ScheduleWakeup,Monitor,CronCreate";

/// Starting points per CLI and mode. `propose`: read, research, delegate to
/// subagents, write only inside the scratch dir (its clones, report.md, outbox/);
/// no shell. `update` and `act`: the CLI's full access, as the user who runs it;
/// the brief bounds `update` to applying fixed releases. Override with
/// `responder.command` for anything else. Claude Code's scheduling tools are off:
/// a run that schedules a wake-up stays open long after its report.
pub static PRESETS: LazyLock<HashMap<(Agent, Mode), Vec<String>>> = LazyLock::new(|| {
    let argv = |parts: &[&str]| -> Vec<String> { parts.iter().map(|s| (*s).to_string()).collect() };
    let full_claude =
        argv(&["claude", "-p", "--output-format", "text", "--dangerously-skip-permissions", "--disallowedTools", CLAUDE_NO_WAITS]);
    let full_codex = argv(&["codex", "exec", "--dangerously-bypass-approvals-and-sandbox", "--skip-git-repo-check", "-"]);
    let full_omp = argv(&["omp", "-p", "--no-session", "@{prompt}"]);
    HashMap::from([
        (
            (Agent::Claude, Mode::Propose),
            argv(&[
                "claude",
                "-p",
                "--output-format",
                "text",
                "--permission-mode",
                "acceptEdits",
                "--allowedTools",
                "Read,Grep,Glob,Write,Edit,WebFetch,WebSearch,Task",
                "--disallowedTools",
                CLAUDE_NO_WAITS,
            ]),
        ),
        ((Agent::Claude, Mode::Update), full_claude.clone()),
        ((Agent::Claude, Mode::Act), full_claude),
        ((Agent::Codex, Mode::Propose), argv(&["codex", "exec", "--sandbox", "workspace-write", "--skip-git-repo-check", "-"])),
        ((Agent::Codex, Mode::Update), full_codex.clone()),
        ((Agent::Codex, Mode::Act), full_codex),
        ((Agent::Omp, Mode::Propose), argv(&["omp", "-p", "--no-session", "--tools", "read,grep,glob,write,edit,task,web_search", "@{prompt}"])),
        ((Agent::Omp, Mode::Update), full_omp.clone()),
        ((Agent::Omp, Mode::Act), full_omp),
    ])
});

/// `argv` (a Claude preset's `propose` argv) with `Bash(<cmd>:*)` for every reach-the-user command added to the
/// `--allowedTools` value: propose runs without a shell, and these are its one exception (Claude Code matches them by
/// prefix). Applied to the preset only, at config load; a user's own `command` is never touched.
pub fn allow_reach(argv: &[String], reach: &[String]) -> Vec<String> {
    if reach.is_empty() {
        return argv.to_vec();
    }
    argv.iter()
        .enumerate()
        .map(|(i, arg)| {
            if i > 0 && argv[i - 1] == "--allowedTools" {
                std::iter::once(arg.clone()).chain(reach.iter().map(|cmd| format!("Bash({cmd}:*)"))).collect::<Vec<_>>().join(",")
            } else {
                arg.clone()
            }
        })
        .collect()
}

/// The argv template for a mode (resolved at config load from `responder.command` or the preset, the preset's
/// `propose` argv for Claude carrying the reach-the-user commands).
pub fn responder_command(config: &Config, mode: Mode) -> Result<&[String]> {
    let r = config.responder.as_ref().ok_or_else(|| anyhow!("no responder configured"))?;
    Ok(r.command.for_mode(mode))
}

/// The first `units` UTF-16 code units of `s` (JS `slice(0, n)`; a surrogate pair is never split).
fn slice_utf16(s: &str, units: usize) -> &str {
    let mut used = 0;
    for (at, c) in s.char_indices() {
        used += c.len_utf16();
        if used > units {
            return &s[..at];
        }
    }
    s
}

/// The brief directory to read: the configured one, or, for the shipped brief that is not on disk (a lone binary),
/// the compiled-in files written into `<workdir>/respond/`.
fn brief_dir(config: &Config, workdir: &Path) -> Result<PathBuf> {
    let r = config.responder.as_ref().ok_or_else(|| anyhow!("no responder configured"))?;
    if r.brief == shipped_brief() && !r.brief.exists() {
        let dir = workdir.join("respond");
        for (name, text) in SHIPPED_BRIEF_FILES {
            write_file_atomic(&dir.join(name), text)?;
        }
        return Ok(dir);
    }
    Ok(r.brief.clone())
}

/// The brief directory's path files: every `<path>.md` besides the shared rules and triage.
fn path_files(dir: &Path) -> Result<Vec<String>> {
    let entries = fs::read_dir(dir).map_err(|e| anyhow!("{}: {e}", dir.display()))?;
    let mut files: Vec<String> =
        entries.filter_map(|e| e.ok()?.file_name().into_string().ok()).filter(|f| f.ends_with(".md") && f != "common.md" && f != "triage.md").collect();
    files.sort();
    Ok(files)
}

/// The standing part of the prompt: the shared rules and the triage brief in full, then the path files the agent
/// reads once triage has picked one, then the user's notes. This is what `{brief}` points at (`brief.md`).
pub fn build_brief(config: &Config, workdir: &Path) -> Result<String> {
    let r = config.responder.as_ref().ok_or_else(|| anyhow!("no responder configured"))?;
    let dir = brief_dir(config, workdir)?;
    let mut lines = vec![
        read_brief(&dir, "common.md")?.trim().to_string(),
        String::new(),
        read_brief(&dir, "triage.md")?.trim().to_string(),
        String::new(),
        "## The path files".to_string(),
        String::new(),
        "Once triage has picked a path, read its file and follow it:".to_string(),
    ];
    for f in path_files(&dir)? {
        lines.push(format!("- {}: {}", f.strip_suffix(".md").unwrap_or(&f), dir.join(&f).display()));
    }
    if let Some(notes) = r.notes.as_deref().filter(|n| !n.is_empty()) {
        lines.extend(["".to_string(), "## Notes from the user".to_string(), String::new(), notes.trim().to_string()]);
    }
    Ok(lines.join("\n"))
}

/// Triage first: the standing brief, then this case.
pub fn build_prompt(config: &Config, _c: &Case, case_file: &Path, mode: Mode, workdir: &Path, clones: &[String]) -> Result<String> {
    let r = config.responder.as_ref().ok_or_else(|| anyhow!("no responder configured"))?;
    let brief = build_brief(config, workdir)?;
    let mode_text = match mode {
        Mode::Act => {
            "ACT. Every place in this case is opted in: update when a fix exists; when none exists and it is exploitable here, work around it, and as a last resort stop restorably."
        }
        Mode::Update => {
            "UPDATE. The user lets fixed releases be applied: update (batched per host and repo) and check the service still works. Nothing else: no workarounds, no stops."
        }
        Mode::Propose => {
            "PROPOSE. Triage as usual and write the exact plan (commands, diffs, verification, undo), but change nothing outside your working directory."
        }
    };
    let case_json = fs::read_to_string(case_file).map_err(|e| anyhow!("{}: {e}", case_file.display()))?;
    let clones_line = if clones.is_empty() {
        "No repo clones were made for this case.".to_string()
    } else {
        format!("Fresh clones of the affected repos (made with the user's own git login): {}", clones.join(", "))
    };
    let rest = [
        String::new(),
        "## This case".to_string(),
        String::new(),
        format!("MODE: {mode_text}"),
        format!("Working directory (yours; scratch): {}", workdir.display()),
        format!("Triage: write {} (format in the triage brief) before you follow the path.", workdir.join("triage.json").display()),
        format!(
            "Tell the user: urgent things only (see the shared rules). Each message is one short plain-text line (what, where, what is being done). Write it to {sent}/NN-<stage>.md (stage: urgent, before, after), run each reach-the-user command below on it, then copy it to {outbox}/NN-<stage>.md: the watcher sends it within seconds and deletes it, so never read it back from there. Everything else goes in the report, which the user's agent reads and summarises.",
            sent = workdir.join("sent").display(),
            outbox = workdir.join("outbox").display()
        ),
        if r.reach.is_empty() {
            "Reach-the-user commands: none set up; the outbox is the only channel (still write each line to sent/NN-<stage>.md first, then copy it to outbox/)."
                .to_string()
        } else {
            format!(
                "Reach-the-user commands (for every urgent, before and after line, run each yourself from your working directory as `<command> < sent/NN-<stage>.md`, one command per call with nothing chained before or after it, and check it exits 0): {}",
                r.reach.iter().map(|cmd| format!("`{cmd}`")).collect::<Vec<_>>().join(", ")
            )
        },
        format!(
            "Report: write {} (format in the brief) last, once every subagent has answered and the work is done: your run ends when you stop, and so does every subagent still running. A run that ends without that report, or with one whose `## Message` starts with `Unfinished`, goes on the retry queue. Machine-readable waits go in a fenced block tagged `{NAME}-wait`.",
            workdir.join("report.md").display()
        ),
        clones_line,
        format!("Case file: {}", case_file.display()),
        String::new(),
        "```json".to_string(),
        case_json.trim().to_string(),
        "```".to_string(),
    ];
    Ok(format!("{brief}\n{}", rest.join("\n")))
}

/// The responder's environment: `base` (the user's), minus every variable the watcher's config reads (tokens, keys)
/// and its own, plus `responder.env`, plus `extra`.
pub fn responder_env(config: &Config, base: &Env, extra: &[(String, String)]) -> Vec<(String, String)> {
    let prefix = format!("{ENV_PREFIX}_");
    let mut env: IndexMap<String, String> = IndexMap::new();
    for (key, value) in base {
        if config.secret_env.contains(key) || key.starts_with(&prefix) || key == "CLASSIFIER_API_KEY" || key == "CLASSIFY_API_KEY" {
            continue;
        }
        env.insert(key.clone(), value.clone());
    }
    if let Some(r) = &config.responder {
        for (key, value) in &r.env {
            env.insert(key.clone(), value.clone());
        }
    }
    for (key, value) in extra {
        env.insert(key.clone(), value.clone());
    }
    env.into_iter().collect()
}

/// What a child's stdout has produced so far; shared with the thread that reads it, so a reader still blocked on a
/// pipe an orphaned grandchild holds open cannot take the bytes already read away with it.
#[derive(Default)]
struct Capture {
    /// The first `max` bytes.
    buf: Mutex<Vec<u8>>,
    /// Every byte read, kept or not: the "child wrote something" signal of the idle rule.
    seen: AtomicU64,
}

/// Reads `reader` into `capture`, keeping at most `max` bytes and draining the rest, so the child never blocks on a full pipe.
fn read_capped(mut reader: impl Read, max: usize, capture: &Capture) {
    let mut buf = [0u8; 65536];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                capture.seen.fetch_add(n as u64, Ordering::SeqCst);
                let mut kept = capture.buf.lock().unwrap_or_else(PoisonError::into_inner);
                let room = max.saturating_sub(kept.len());
                kept.extend_from_slice(&buf[..n.min(room)]);
            }
        }
    }
}

/// How long a written report may sit unchanged, with the child silent, before the run is ended: a CLI (`claude -p`)
/// can schedule a wake-up after its report and hold the case open for nothing.
const REPORT_IDLE: Duration = Duration::from_secs(120);

/// How long a child gets between SIGTERM (idle end) and SIGKILL.
const KILL_AFTER: Duration = Duration::from_secs(10);

/// How long to wait, once an idle-ended child is gone, for its stdout to close before taking what was read.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// The signs that a response is still working: any change resets the idle clock.
#[derive(PartialEq, Eq)]
struct Activity {
    /// Modified time and size of the report, when it exists.
    report: Option<(SystemTime, u64)>,
    /// Bytes the child wrote to stdout.
    stdout: u64,
    /// Per watched directory: entry count and the newest entry's modified time.
    dirs: Vec<(usize, Option<SystemTime>)>,
}

/// End the run once the report is written and nothing has changed for `after`.
struct Idle<'a> {
    report: &'a Path,
    /// `outbox/` and `sent/`: a new message there is activity.
    dirs: Vec<PathBuf>,
    after: Duration,
}

impl Idle<'_> {
    fn activity(&self, stdout: u64) -> Activity {
        let report = fs::metadata(self.report).ok().and_then(|m| Some((m.modified().ok()?, m.len())));
        let dirs = self
            .dirs
            .iter()
            .map(|dir| {
                let mut count = 0;
                let mut newest: Option<SystemTime> = None;
                for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
                    count += 1;
                    newest = newest.max(entry.metadata().ok().and_then(|m| m.modified().ok()));
                }
                (count, newest)
            })
            .collect();
        Activity { report, stdout, dirs }
    }
}

/// One child to run: exactly `env`, `input` on stdin, stderr dropped.
struct ChildSpec<'a> {
    argv: &'a [String],
    env: &'a [(String, String)],
    cwd: Option<&'a Path>,
    input: &'a [u8],
    /// SIGTERM at this time (nothing harder).
    timeout: Duration,
    /// Bytes of stdout to keep.
    capture: usize,
    idle: Option<Idle<'a>>,
}

/// What a child did.
struct Ran {
    /// The exit code (`None`: did not start, or killed by a signal).
    code: Option<i32>,
    /// The first `capture` bytes of stdout.
    stdout: Vec<u8>,
    /// The first `capture` bytes of stderr, at most 64 KiB (a failing CLI says why there).
    stderr: Vec<u8>,
    /// The idle rule ended it (SIGTERM, SIGKILL after 10 s), so a missing exit code is not a failure.
    idle_ended: bool,
    /// The command ran out of time.
    timed_out: bool,
    /// The command could not be started at all.
    unstarted: bool,
}

/// Runs the child. `on_spawn` is told the pid once it runs, or `None` when it could not start.
fn run_child(spec: &ChildSpec, on_spawn: impl FnOnce(Option<u32>)) -> Ran {
    let failed = Ran { code: None, stdout: Vec::new(), stderr: Vec::new(), idle_ended: false, timed_out: false, unstarted: true };
    let Some((program, args)) = spec.argv.split_first() else {
        on_spawn(None);
        return failed;
    };
    let mut cmd = Command::new(program);
    cmd.args(args).env_clear().envs(spec.env.iter().map(|(k, v)| (k.as_str(), v.as_str()))).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    util::own_process_group(&mut cmd);
    if let Some(cwd) = spec.cwd {
        cmd.current_dir(cwd);
    }
    let Ok(mut child) = cmd.spawn() else {
        on_spawn(None);
        return failed;
    };
    let pid = child.id();
    on_spawn(Some(pid));
    // Signals go to the whole group: the agent's own subprocesses stop with it.
    let signal = |sig: libc::c_int| util::kill_group(pid, sig);
    if let Some(mut stdin) = child.stdin.take() {
        let input = spec.input.to_vec();
        // The agent may exit without reading its prompt: a broken pipe is not an error. Dropping closes stdin.
        thread::spawn(move || {
            let _ = stdin.write_all(&input);
        });
    }
    let capture = Arc::new(Capture::default());
    let (closed_tx, closed_rx) = mpsc::channel::<()>();
    let stdout = child.stdout.take().expect("stdout is piped");
    let (reader_capture, max) = (Arc::clone(&capture), spec.capture);
    thread::spawn(move || {
        read_capped(stdout, max, &reader_capture);
        let _ = closed_tx.send(());
    });
    let err_capture = Arc::new(Capture::default());
    let (err_closed_tx, err_closed_rx) = mpsc::channel::<()>();
    let stderr = child.stderr.take().expect("stderr is piped");
    let (reader_capture, max) = (Arc::clone(&err_capture), spec.capture.min(64 * 1024));
    thread::spawn(move || {
        read_capped(stderr, max, &reader_capture);
        let _ = err_closed_tx.send(());
    });

    let started = Instant::now();
    let deadline = started + spec.timeout;
    let mut terminated_at: Option<Instant> = None;
    let mut idle_ended_at: Option<Instant> = None;
    let mut killed = false;
    let mut last = spec.idle.as_ref().map(|idle| idle.activity(0));
    let mut changed_at = started;
    let mut next_sample = started;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(_) => break None,
        }
        let now = Instant::now();
        if let (Some(idle), Some(last), None) = (&spec.idle, last.as_mut(), idle_ended_at)
            && now >= next_sample
        {
            next_sample = now + Duration::from_millis(250);
            let current = idle.activity(capture.seen.load(Ordering::SeqCst));
            if current != *last {
                *last = current;
                changed_at = now;
            } else if last.report.is_some_and(|(_, len)| len > 0) && now.duration_since(changed_at) >= idle.after {
                signal(libc::SIGTERM);
                idle_ended_at = Some(now);
            }
        }
        if let Some(at) = idle_ended_at {
            if !killed && now.duration_since(at) >= KILL_AFTER {
                signal(libc::SIGKILL);
                killed = true;
            }
        } else if terminated_at.is_none() && now >= deadline {
            signal(libc::SIGTERM);
            terminated_at = Some(now);
        }
        thread::sleep(Duration::from_millis(20));
    };
    let idle_ended = idle_ended_at.is_some();
    // The child is gone; what it left in its group (an agent's subprocesses) gets the rest of its grace after the
    // SIGTERM, then SIGKILL, so nothing outlives a run that was cut off.
    if let Some(since) = idle_ended_at.or(terminated_at) {
        while util::group_alive(pid) {
            if Instant::now().duration_since(since) >= KILL_AFTER {
                util::kill_group(pid, libc::SIGKILL);
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    // Normally the pipe closes with the child. An idle-ended child's own children may hold it open: take what was read.
    if idle_ended {
        let _ = closed_rx.recv_timeout(DRAIN_GRACE);
    } else {
        let _ = closed_rx.recv();
    }
    let _ = err_closed_rx.recv_timeout(DRAIN_GRACE);
    let stdout = std::mem::take(&mut *capture.buf.lock().unwrap_or_else(PoisonError::into_inner));
    let stderr = std::mem::take(&mut *err_capture.buf.lock().unwrap_or_else(PoisonError::into_inner));
    Ran { code: status.and_then(|s| s.code()), stdout, stderr, idle_ended, timed_out: terminated_at.is_some(), unstarted: false }
}

/// Clones the case's repos with the user's own git login (never the read-only inventory token).
fn clone_repos(config: &Config, base: &Env, c: &Case, workdir: &Path) -> Vec<String> {
    let repos: Vec<&str> = c.places.iter().filter_map(|p| p.r#where.strip_prefix("repo:")).collect::<IndexSet<_>>().into_iter().take(5).collect();
    let mut out = Vec::new();
    for repo in repos {
        let target = workdir.join("repos").join(repo.replacen('/', "__", 1));
        let argv: Vec<String> = ["git", "clone", "--depth", "50", "--quiet"]
            .iter()
            .map(|s| (*s).to_string())
            .chain([format!("https://github.com/{repo}.git"), target.to_string_lossy().into_owned()])
            .collect();
        let env = responder_env(config, base, &[("GIT_TERMINAL_PROMPT".to_string(), "0".to_string())]);
        let spec = ChildSpec { argv: &argv, env: &env, cwd: None, input: b"", timeout: Duration::from_secs(180), capture: 0, idle: None };
        let code = run_child(&spec, |_| {}).code;
        if code == Some(0) {
            out.push(target.to_string_lossy().into_owned());
        }
    }
    out
}

/// Sends and removes what the responder put in its outbox: urgent one-liners only (the brief allows nothing else).
/// A line `told` already holds (an earlier run of the same case sent it) is dropped unsent, so a retry never repeats
/// itself; what goes out is added to `told`. Returns how many it sent.
fn relay_outbox(config: &Config, c: &Case, workdir: &Path, notify: &Notifier, told: &Mutex<Vec<String>>) -> usize {
    let outbox = workdir.join("outbox");
    let Ok(entries) = fs::read_dir(&outbox) else { return 0 };
    let mut files: Vec<String> = entries.filter_map(|e| e.ok()?.file_name().into_string().ok()).filter(|f| !f.starts_with('.')).collect();
    files.sort();
    let mut sent = 0;
    for file in files {
        let path = outbox.join(file);
        let Ok(bytes) = fs::read(&path) else { continue };
        let text = String::from_utf8_lossy(&bytes).trim().to_string();
        let _ = fs::remove_file(&path);
        if text.is_empty() {
            continue;
        }
        let title = redact(config, &text);
        {
            let mut told = told.lock().unwrap_or_else(PoisonError::into_inner);
            if told.contains(&title) {
                continue;
            }
            told.push(title.clone());
        }
        notify(&Notice {
            event: NotifyEvent::Urgent,
            title,
            text: String::new(),
            key: Some(c.key.clone()),
            severity: Some(c.severity.as_str().to_string()),
            urls: None,
            report_path: c.report.clone(),
        });
        sent += 1;
    }
    sent
}

/// Every response still running in this process; a one-shot cycle waits for them before exiting.
static RUNNING: Mutex<Vec<JoinHandle<()>>> = Mutex::new(Vec::new());

/// Waits until no response is running (TS: `await Promise.all(running)`), including ones started while waiting.
/// Polls rather than joining, so concurrent callers (tests share the process) all see every response finish.
pub fn wait_running() {
    while running_count() > 0 {
        thread::sleep(Duration::from_millis(10));
    }
}

/// How many responses are still running in this process.
pub fn running_count() -> usize {
    let mut handles = RUNNING.lock().unwrap_or_else(PoisonError::into_inner);
    handles.retain(|h| !h.is_finished());
    handles.len()
}

/// What `start_response_with` can change.
#[derive(Debug, Clone, Default)]
pub struct StartOptions<'a> {
    /// Dispatched by a cycle, so its result goes into the batch's report rather than a report of its own.
    pub batch: bool,
    /// The environment the responder's is derived from. Default: the process environment.
    pub env: Option<&'a Env>,
    /// How long a written, unchanged report with a silent child ends the run. Default: 2 minutes.
    pub report_idle: Option<Duration>,
    /// Another run of a case whose last run did not finish: the urgent lines that run sent are not sent again, and
    /// a failure of this run does not announce itself (the retry queue does).
    pub retry: bool,
}

/// Starts one response, not part of a batch: see `start_response_with`.
pub fn start_response(config: &Config, c: &Case, case_file: &Path, mode: Mode, notify: Notifier) -> Result<()> {
    start_response_with(config, c, case_file, mode, notify, &StartOptions::default())
}

/// Starts one response and returns once the agent is running (or failed to start). Its completion
/// (report, waits, final message) is written to `responses/<slug>.json` and
/// merged into the case by the next cycle. Its outbox lines go out as urgent
/// one-liners.
pub fn start_response_with(config: &Config, c: &Case, case_file: &Path, mode: Mode, notify: Notifier, options: &StartOptions) -> Result<()> {
    let r = config.responder.as_ref().ok_or_else(|| anyhow!("no responder configured"))?;
    let started_at = iso(util::now());
    let stamp: String = started_at.chars().filter(char::is_ascii_digit).take(14).collect();
    let workdir = config.state_dir.join("work").join(format!("{}-{stamp}", slug(&c.key)));
    for sub in ["outbox", "sent"] {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(workdir.join(sub))?;
    }
    let base = options.env.cloned().unwrap_or_else(process_env);
    let clones = clone_repos(config, &base, c, &workdir);
    let record_name = format!("responses/{}.json", slug(&c.key));
    // A retry does not repeat what the run before it already told the user.
    let earlier = if options.retry { read_state::<ResponseRecord>(&config.state_dir, &record_name).map(|r| r.urgent).unwrap_or_default() } else { Vec::new() };
    let mut prompt = build_prompt(config, c, case_file, mode, &workdir, &clones)?;
    if !earlier.is_empty() {
        prompt.push_str("\n## Already sent\n\nAn earlier run of this case sent these urgent lines already, by the watcher or by your reach commands. Do not send them again; send a line only for something new:\n");
        for line in &earlier {
            prompt.push_str(&format!("- {line}\n"));
        }
    }
    let prompt_file = workdir.join("prompt.md");
    write_file_atomic(&prompt_file, &prompt)?;
    let brief_file = workdir.join("brief.md");
    write_file_atomic(&brief_file, &build_brief(config, &workdir)?)?;
    let template = responder_command(config, mode)?;
    let report_file = workdir.join("report.md");
    let argv: Vec<String> = template
        .iter()
        .map(|arg| {
            arg.replace("{prompt}", &prompt_file.to_string_lossy())
                .replace("{brief}", &brief_file.to_string_lossy())
                .replace("{case}", &case_file.to_string_lossy())
                .replace("{report}", &report_file.to_string_lossy())
                .replace("{workdir}", &workdir.to_string_lossy())
                .replace("{mode}", mode.as_str())
        })
        .collect();
    let via_file = template.iter().any(|arg| arg.contains("{prompt}"));
    let record = ResponseRecord {
        key: c.key.clone(),
        state: ResponseState::Running,
        started_at,
        finished_at: None,
        report: None,
        waits: None,
        triage: None,
        error: None,
        pid: None,
        urgent: earlier.clone(),
    };
    write_state(&config.state_dir, &record_name, &record)?;

    let env = responder_env(
        config,
        &base,
        &[
            (format!("{ENV_PREFIX}_CASE"), case_file.to_string_lossy().into_owned()),
            (format!("{ENV_PREFIX}_WORKDIR"), workdir.to_string_lossy().into_owned()),
            (format!("{ENV_PREFIX}_MODE"), mode.as_str().to_string()),
        ],
    );
    let job = Job {
        config: config.clone(),
        case: c.clone(),
        notify,
        batch: options.batch,
        retry: options.retry,
        earlier,
        workdir,
        argv,
        report_idle: options.report_idle.unwrap_or(REPORT_IDLE),
        env,
        cwd: r.cwd.clone(),
        input: if via_file { Vec::new() } else { prompt.into_bytes() },
        timeout: Duration::from_secs_f64(r.timeout_minutes * 60.0),
        record,
        record_name,
    };
    let (spawned_tx, spawned_rx) = mpsc::channel::<()>();
    let handle = thread::Builder::new().name(format!("response-{}", slug(&c.key))).spawn(move || {
        if let Err(e) = job.run(&spawned_tx) {
            util::log(&format!("responder: {}: {e:#}", job.case.key));
        }
        // Whatever happened, the caller is waiting for the start.
        let _ = spawned_tx.send(());
    })?;
    {
        let mut handles = RUNNING.lock().unwrap_or_else(PoisonError::into_inner);
        handles.retain(|h| !h.is_finished());
        handles.push(handle);
    }
    let _ = spawned_rx.recv();
    Ok(())
}

/// One response, owned by its thread.
struct Job {
    config: Config,
    case: Case,
    notify: Notifier,
    batch: bool,
    retry: bool,
    /// The urgent lines an earlier run of the case sent.
    earlier: Vec<String>,
    workdir: PathBuf,
    report_idle: Duration,
    argv: Vec<String>,
    env: Vec<(String, String)>,
    cwd: Option<PathBuf>,
    input: Vec<u8>,
    timeout: Duration,
    record: ResponseRecord,
    record_name: String,
}

impl Job {
    fn run(&self, spawned: &mpsc::Sender<()>) -> Result<()> {
        let (config, c, workdir) = (&self.config, &self.case, &self.workdir);
        let mut record = self.record.clone();
        let told = Mutex::new(self.earlier.clone());
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let report_file = workdir.join("report.md");
        let ran = thread::scope(|scope| {
            let (told, notify) = (&told, &self.notify);
            let relay = scope.spawn(move || {
                while let Err(RecvTimeoutError::Timeout) = stop_rx.recv_timeout(Duration::from_secs(3)) {
                    relay_outbox(config, c, workdir, notify, told);
                }
            });
            let spec = ChildSpec {
                argv: &self.argv,
                env: &self.env,
                cwd: Some(self.cwd.as_deref().unwrap_or(workdir)),
                input: &self.input,
                timeout: self.timeout,
                capture: 2_000_000,
                idle: Some(Idle { report: &report_file, dirs: vec![workdir.join("outbox"), workdir.join("sent")], after: self.report_idle }),
            };
            let result = run_child(&spec, |pid| {
                if pid.is_some() {
                    record.pid = pid;
                    if let Err(e) = write_state(&config.state_dir, &self.record_name, &record) {
                        util::log(&format!("responder: {}: {e:#}", c.key));
                    }
                }
                let _ = spawned.send(());
            });
            drop(stop_tx);
            let _ = relay.join();
            result
        });
        let (code, idle_ended) = (ran.code, ran.idle_ended);
        if idle_ended {
            util::log(&format!("responder {}: report written and idle for {}; ended the run", c.key, describe_duration(self.report_idle)));
        }
        relay_outbox(config, c, workdir, &self.notify, &told);
        let told = told.into_inner().unwrap_or_else(PoisonError::into_inner);

        let stdout = String::from_utf8_lossy(&ran.stdout).into_owned();
        let written = fs::read(workdir.join("report.md")).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
        let exit = code.map_or_else(|| "null".to_string(), |n| n.to_string());
        let has_report = !written.trim().is_empty() || !stdout.trim().is_empty();
        let unfinished = unfinished(&written);
        let report = redact(
            config,
            &if !written.trim().is_empty() {
                written
            } else if !stdout.is_empty() {
                stdout.clone()
            } else {
                format!("(the agent wrote no report; exit {exit})")
            },
        );
        let report_path = c.report.as_deref().map(PathBuf::from).unwrap_or_else(|| workdir.join("report.md"));
        write_file_atomic(&report_path, &format!("{report}\n"))?;
        let triage = parse_triage(config, &workdir.join("triage.json"));
        // An idle end is the normal way a finished run that would not exit stops: no exit code, not a failure. A run
        // counts as finished only with its report.md and a `## Message` that doesn't say it is unfinished: an agent that
        // ends its turn while subagents work leaves only a stub ("still running, I'll wait"), and they die with it.
        let ok = (code == Some(0) || idle_ended) && unfinished.is_none();
        record.state = if ok { ResponseState::Done } else { ResponseState::Failed };
        record.finished_at = Some(iso(util::now()));
        record.report = c.report.clone();
        record.waits = Some(parse_waits(&report));
        record.triage = triage.clone();
        if !ok {
            let program = self.argv.first().map_or("", String::as_str);
            let reason = failure_reason(&ran, &stdout, program, self.timeout, has_report, unfinished);
            record.error = Some(slice_utf16(&redact(config, &reason), 300).to_string());
        }
        record.urgent = told.clone();
        record.pid = None;
        write_state(&config.state_dir, &self.record_name, &record)?;

        let message = message_of(&report);
        // The brief says to send "exploitable now" at once; if the agent rated it act today but sent nothing, the one line goes out here.
        let rating = triage.as_ref().and_then(|t| t.rating.clone()).unwrap_or_else(|| final_rating(c, &message).as_str().to_string());
        if ok && told.is_empty() && rating == "act today" {
            (self.notify)(&Notice {
                event: NotifyEvent::Urgent,
                title: format!("{} ({})", message.split('\n').next().unwrap_or("").trim(), slice_utf16(&c.title, 100)),
                text: String::new(),
                key: Some(c.key.clone()),
                severity: Some(c.severity.as_str().to_string()),
                urls: None,
                report_path: c.report.clone(),
            });
        }
        // A failed run is announced by the retry queue (one line per cycle), a retry's by its own result only when it finishes.
        if !self.batch && !(self.retry && !ok) {
            (self.notify)(&Notice {
                event: NotifyEvent::Report,
                title: format!("{}: {}", if ok { "Done" } else { "Queued to retry" }, slice_utf16(&c.title, 150)),
                text: if ok { message } else { record.error.clone().unwrap_or_default() },
                key: Some(c.key.clone()),
                severity: Some(c.severity.as_str().to_string()),
                urls: None,
                report_path: c.report.clone(),
            });
        }
        // Clones are scratch; the prompt and report stay with the state for the record.
        let _ = fs::remove_dir_all(workdir.join("repos"));
        Ok(())
    }
}

/// Why a finished-looking run is not finished, or `None` when its report is: `report.md` holds a `## Message` section
/// that does not open with `Unfinished`.
fn unfinished(report: &str) -> Option<&'static str> {
    static HEAD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^##\s*Message\s*$").expect("valid regex"));
    if report.trim().is_empty() {
        return Some("ended without writing report.md");
    }
    if !HEAD.is_match(report) {
        return Some("ended before its report was finished (report.md has no `## Message`)");
    }
    let message = message_of(report);
    if message.trim().is_empty() {
        return Some("ended before its report was finished (an empty `## Message`)");
    }
    message.trim_start().get(..10).is_some_and(|w| w.eq_ignore_ascii_case("unfinished")).then_some("its report says it is unfinished")
}

/// Why a run did not finish: how it ended, and what the agent said about it.
fn failure_reason(ran: &Ran, stdout: &str, program: &str, timeout: Duration, has_report: bool, unfinished: Option<&str>) -> String {
    let how = if ran.unstarted {
        return format!("could not start `{program}` (is it installed on this machine?)");
    } else if ran.timed_out {
        format!("timed out after {}", describe_duration(timeout))
    } else {
        match (ran.code, unfinished) {
            (Some(0), _) if !has_report => "exited without a report".to_string(),
            (Some(0), Some(why)) => why.to_string(),
            (None, Some(why)) if ran.idle_ended => why.to_string(),
            (Some(n), _) => format!("exit {n}"),
            (None, _) => "killed by a signal".to_string(),
        }
    };
    crate::retry::failure_reason(&how, stdout, &String::from_utf8_lossy(&ran.stderr))
}

/// `2 min`, `1 s`: an idle period as the log line says it.
fn describe_duration(d: Duration) -> String {
    if d.as_secs() > 0 && d.as_secs().is_multiple_of(60) && d.subsec_nanos() == 0 {
        format!("{} min", d.as_secs() / 60)
    } else {
        format!("{} s", d.as_secs_f64())
    }
}

/// The triage the agent wrote, when it names a known path; anything else is left out (the report still says what it did).
pub fn parse_triage(config: &Config, file: &Path) -> Option<Triage> {
    let value: serde_json::Value = serde_json::from_str(&fs::read_to_string(file).ok()?).ok()?;
    let path: TriagePath = serde_json::from_value(value.get("path")?.clone()).ok()?;
    let why = value.get("why")?.as_str()?;
    Some(Triage {
        path,
        why: slice_utf16(&redact(config, why), 300).to_string(),
        rating: value.get("rating").and_then(|v| v.as_str()).map(str::to_string),
        fix_released: value.get("fixReleased").and_then(|v| v.as_bool()),
        exploitable: value.get("exploitable").and_then(|v| v.as_str()).map(str::to_string),
    })
}

/// The `## Message` section of a report (what the user is told at the end), else its opening.
pub fn message_of(report: &str) -> String {
    // JS: /^##\s*Message\s*\n([\s\S]*?)(?=^##\s|$(?![\s\S]))/m: the section runs to the next `##` heading line or the
    // end. The regex crate has no lookahead, so the end is searched separately.
    static HEAD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^##\s*Message\s*\n").expect("valid regex"));
    static NEXT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^##\s").expect("valid regex"));
    if let Some(head) = HEAD.find(report) {
        let start = head.end();
        // `find_at` keeps the text before `start` as context, so `^` still means a line start.
        let end = NEXT.find_at(report, start).map_or(report.len(), |m| m.start());
        return report[start..end].trim().to_string();
    }
    report.split('\n').take(30).collect::<Vec<_>>().join("\n").trim().to_string()
}

/// Responses whose process is gone (the watcher restarted mid-response) are marked failed, so the next cycle stops waiting on them.
pub fn recover_responses(config: &Config) -> Vec<String> {
    let mut out = Vec::new();
    for mut record in read_responses(&config.state_dir) {
        if record.state != ResponseState::Running {
            continue;
        }
        // SAFETY: signal 0 only checks that the process exists and may be signalled.
        let alive = record.pid.is_some_and(|pid| pid != 0 && unsafe { libc::kill(pid as libc::pid_t, 0) } == 0);
        if alive {
            continue;
        }
        record.state = ResponseState::Failed;
        record.finished_at = Some(iso(util::now()));
        record.error = Some("interrupted: the watcher stopped while it ran".to_string());
        let name = format!("responses/{}.json", slug(&record.key));
        let _ = write_state(&config.state_dir, &name, &record);
        out.push(record.key);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::read_state;

    #[test]
    fn message_is_the_section_up_to_the_next_heading_else_the_opening() {
        assert_eq!(message_of("## Message\nPinned it.\n\n## Details\nmore\n"), "Pinned it.");
        assert_eq!(message_of("# Report\n\n## Message\n\nOnly this.\nAnd this.\n"), "Only this.\nAnd this.");
        assert_eq!(message_of("## Message\n## Details\nx"), "", "an empty section is empty, not the opening");
        assert_eq!(message_of("### Message\nnot a match\n"), "### Message\nnot a match");
        assert_eq!(message_of("no headings here\nsecond line"), "no headings here\nsecond line");
        let long: String = (1..=40).map(|n| format!("line {n}\n")).collect();
        assert_eq!(message_of(&long).lines().count(), 30);
    }

    #[test]
    fn recorded_responses_with_a_dead_process_are_marked_failed() {
        let dir = std::env::temp_dir().join(format!("cvecondor-recover-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let raw = serde_json::json!({ "stateDir": dir, "collectors": [{ "type": "host" }], "responder": { "command": ["true"] } });
        let config = crate::config::build_config(&raw, &dir.join("config.json"), &Env::new()).expect("builds");
        let running = ResponseRecord {
            key: "CVE-1".into(),
            state: ResponseState::Running,
            started_at: "2026-10-22T06:00:00.000Z".into(),
            finished_at: None,
            report: None,
            waits: None,
            triage: None,
            error: None,
            pid: Some(u32::MAX - 1),
            urgent: Vec::new(),
        };
        write_state(&dir, "responses/cve-1.json", &running).expect("writes");
        write_state(&dir, "responses/cve-2.json", &ResponseRecord { key: "CVE-2".into(), state: ResponseState::Done, ..running.clone() }).expect("writes");
        write_state(&dir, "responses/cve-3.json", &ResponseRecord { key: "CVE-3".into(), pid: Some(std::process::id()), ..running.clone() }).expect("writes");
        assert_eq!(recover_responses(&config), ["CVE-1"], "a finished response and one whose process lives are left alone");
        let after: ResponseRecord = read_state(&dir, "responses/cve-1.json").expect("reads");
        assert_eq!((after.state, after.error.as_deref()), (ResponseState::Failed, Some("interrupted: the watcher stopped while it ran")));
        let _ = fs::remove_dir_all(&dir);
    }
}
