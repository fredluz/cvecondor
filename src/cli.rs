// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! The command line: run as a daemon, run one cycle (cron, GitHub Actions),
//! refresh the inventory, and look at what the watcher sees.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use indexmap::{IndexMap, IndexSet};
use jiff::Timestamp;
use regex::Regex;
use serde::Serialize;

use crate::config::{Config, Mode, NotifyEvent, load_config, load_env_file, process_env, redact};
use crate::feeds::{FeedState, NEWS_SOURCES, SOURCES, SourceKind};
use crate::fixes::{describe_wait, parse_waits};
use crate::http::{Fetch, Net, Request, Response};
use crate::inbox::{keep, mark_read, unread};
use crate::inventory::{CollectOptions, collect_inventory};
use crate::matching::{OsvRecord, Severity, describe_secret, osv_family, osv_fixes, osv_query, osv_record, osv_severity};
use crate::name::{ENV_PREFIX, NAME, VERSION};
use crate::notify::{Notice, Notifier, SendResult, send_notice};
use crate::relay;
use crate::responder::{StartOptions, recover_responses, running_count, start_response_with, wait_running};
use crate::secrets::Exposure;
use crate::state::{read_state, slug, with_lock, write_file_atomic, write_state};
use crate::types::{Inventory, InventoryItem};
use crate::util::{self, iso, parse_time};
use crate::vendors::catalog::VENDORS;
use crate::vendors::detect_vendors;
use crate::retry;
use crate::watch::{
    Affected, AssessInput, Assessment, Case, CaseState, CycleDeps, CycleSummary, HandledBy, Known, Rating, ResponseRecord, ResponseState, Run, assess,
    case_file, case_mode, merge_responses, prepare_case, read_responses, report_finished_batches, report_path, run_cycle,
};

fn help() -> String {
    format!(
        "{NAME} {VERSION}: watches vulnerability feeds and vendor incidents against what you run.

Usage: {NAME} <command> [--config FILE]

  run                 daemon: a cycle every pollMinutes, inventory every inventoryHours
  cycle               one cycle now (refreshes a stale inventory first); waits for responders
  inventory [--out F] refresh the inventory now (all collectors, read-only)
  baseline [--out F]  what is vulnerable or exposed today: critical/high per place, secrets, vendors
  status              last cycle, sources, collectors, open cases, unread inbox
  inbox [--all] [--peek]
                      what the watcher kept for you since you last read it (everything not urgent), then marks it read
  vendors [--catalog [TERM]]  the vendors detected (and named in the config), with evidence and feeds;
                      --catalog lists the shipped catalogue's ids
  secrets             secrets found where they shouldn't be (names, places, fingerprints)
  notify-test         send a test notice through every notifier
  replay --source ID --file F [--only TEXT] [--inventory FILE] [--respond]
                      replay a feed document against your inventory (or the inventory file given) in a throwaway state dir;
                      prints each case's rating, fix and the mode your agent would run in; --respond runs your agent
  respond KEY [--mode propose|update|act]
                      run the configured responder on one case now (KEY: case key or CVE/GHSA id) and wait for it
  record KEY --file REPORT
                      record a case you handled yourself: its report, and the cvecondor-wait block (what it waits for)
  follow [--once | --test] [--config FILE]
                      on your own machine: each urgent line from the watcher opens a session of your agent
                      (reads follow.json, not the watcher's config); --once polls once, --test sends a test line

Config: --config FILE, or {ENV_PREFIX}_CONFIG, or ~/.config/{NAME}/config.json"
    )
}

/// Prints a line to stdout; a closed pipe is not an error.
fn say(text: &str) {
    let _ = writeln!(std::io::stdout(), "{text}");
}

fn log(line: &str) {
    util::log(line);
}

/// `JSON.stringify(value, null, 1) + "\n"`.
fn json_pretty<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    let mut buf = Vec::new();
    let mut serializer = serde_json::Serializer::with_formatter(&mut buf, serde_json::ser::PrettyFormatter::with_indent(b" "));
    value.serialize(&mut serializer)?;
    buf.push(b'\n');
    Ok(String::from_utf8(buf)?)
}

/// Writes a file readable by its owner only (the mode applies when the file is created).
fn write_private(path: &Path, text: &str) -> Result<()> {
    let mut file = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path).with_context(|| format!("open {}", path.display()))?;
    file.write_all(text.as_bytes()).with_context(|| format!("write {}", path.display()))
}

/// Every notice is kept in the inbox (a file under reports/, a line in inbox.jsonl) for the agent in charge; a notifier
/// gets it only when it listens for that event (by default `urgent` only).
fn notifier(config: &Config) -> Notifier {
    let config = config.clone();
    Arc::new(move |notice: &Notice| {
        let mut errors = Vec::new();
        if let Err(e) = keep(&config.state_dir, notice, util::now()) {
            errors.push(redact(&config, &format!("inbox: {e:#}")));
        }
        if !config.notify.iter().any(|n| n.events.contains(&notice.event)) {
            if notice.event == NotifyEvent::Urgent {
                log(&format!("urgent (no notifier listens for it): {}", notice.title));
            }
            return SendResult { sent: if errors.is_empty() { vec!["inbox".to_string()] } else { Vec::new() }, errors };
        }
        let titled = Notice { title: format!("[{NAME}] {}", notice.title), ..notice.clone() };
        let mut result = send_notice(&config, &titled, &Net, util::now());
        for e in &result.errors {
            log(&format!("notify: {e}"));
        }
        result.errors.splice(0..0, errors);
        result
    })
}

/// What a cycle needs from outside, wired to this process. `respond`: start the configured responder for a case
/// (absent without one); each start says whether it reports through its batch and whether it is a retry.
fn with_deps<R>(config: &Config, respond: bool, fetch: &dyn Fetch, f: impl FnOnce(&CycleDeps) -> R) -> R {
    let notify = notifier(config);
    let start = |c: &Case, file: &Path, mode: Mode, run: Run| {
        start_response_with(config, c, file, mode, notify.clone(), &StartOptions { batch: run.batch, retry: run.retry, ..StartOptions::default() })
    };
    let now = util::now;
    let logger = |line: &str| log(line);
    let deps = CycleDeps {
        fetch,
        now: &now,
        judge: None,
        judge_vendor: None,
        respond: if respond && config.responder.is_some() { Some(&start) } else { None },
        notify: notify.clone(),
        log: &logger,
    };
    f(&deps)
}

/// `None`: another inventory refresh holds the lock.
fn refresh(config: &Config) -> Result<Option<Inventory>> {
    with_lock(&config.state_dir, "inventory", || -> Result<Inventory> {
        let previous: Option<Inventory> = read_state(&config.state_dir, "inventory.json");
        let logger = |line: &str| log(line);
        let inventory = collect_inventory(config, previous.as_ref(), CollectOptions { log: Some(&logger), ..CollectOptions::default() });
        write_state(&config.state_dir, "inventory.json", &inventory)?;
        Ok(inventory)
    })
    .transpose()
}

fn inventory_text(inventory: &Inventory) -> String {
    let mut lines = vec![format!(
        "Inventory {}: {} items, {} secret findings, {} vendor signals",
        inventory.collected_at,
        inventory.items.len(),
        inventory.secrets.len(),
        inventory.signals.len()
    )];
    for (name, s) in &inventory.sources {
        let error = s.error.as_deref().filter(|e| !e.is_empty()).map(|e| format!("  {e}")).unwrap_or_default();
        let warnings = match s.warnings.as_deref() {
            Some(w) if !w.is_empty() => format!("\n{}", w.iter().map(|w| format!("      warning: {w}")).collect::<Vec<_>>().join("\n")),
            _ => String::new(),
        };
        lines.push(format!("  {name:<12} {} {:>6} items {:>4} secrets{error}{warnings}", if s.ok { "ok  " } else { "FAIL" }, s.items, s.secrets));
    }
    lines.join("\n")
}

fn cycle_text(s: &CycleSummary) -> String {
    let mut lines = vec![format!(
        "Cycle {}: {} sources polled, {} new items, {} vendors watched, {} ms{}",
        s.at,
        s.polled,
        s.fresh,
        s.vendors,
        s.duration_ms,
        s.skipped.as_deref().filter(|k| !k.is_empty()).map(|k| format!(", skipped: {k}")).unwrap_or_default()
    )];
    if s.first_read > 0 {
        lines.push(format!(
            "{} source(s) read for the first time: what they already carry is recorded as history, not news (new items from now on count).",
            s.first_read
        ));
    }
    if !s.osv_queried.is_empty() {
        lines.push(format!("OSV queried: {}", s.osv_queried.join(" ")));
    }
    if !s.new_cases.is_empty() {
        lines.push(format!("New cases: {}", s.new_cases.join(", ")));
    }
    if !s.reopened.is_empty() {
        lines.push(format!("Reopened (fix shipped): {}", s.reopened.join(", ")));
    }
    if !s.dispatched.is_empty() {
        lines.push(format!("Dispatched: {}", s.dispatched.join(", ")));
    }
    if !s.queued.is_empty() {
        lines.push(format!("Queued to retry (the response did not finish): {}", s.queued.join(", ")));
    }
    if !s.retried.is_empty() {
        lines.push(format!("Retried: {}", s.retried.join(", ")));
    }
    if s.secrets_told > 0 {
        lines.push(format!("Secrets told: {}", s.secrets_told));
    }
    if !s.errors.is_empty() {
        lines.push(format!("Errors:\n{}", s.errors.iter().map(|e| format!("  {e}")).collect::<Vec<_>>().join("\n")));
    }
    lines.join("\n")
}

fn cycle(config: &Config, wait: bool, force_inventory: bool) -> Result<String> {
    let mut out = Vec::new();
    let inventory: Option<Inventory> = read_state(&config.state_dir, "inventory.json");
    let stale = |inventory: &Inventory| {
        parse_time(&inventory.collected_at).is_some_and(|at| (util::now().as_millisecond() - at.as_millisecond()) as f64 > config.inventory_hours * 3_600_000.0)
    };
    if (force_inventory || inventory.as_ref().is_none_or(stale))
        && let Some(fresh) = refresh(config)?
    {
        out.push(inventory_text(&fresh));
    }
    for key in recover_responses(config) {
        out.push(format!("Response for {key} was interrupted; marked failed."));
    }
    let summary = with_lock(&config.state_dir, "cycle", || with_deps(config, true, &Net, |deps| run_cycle(config, deps))).transpose()?;
    out.push(summary.as_ref().map_or_else(|| "A cycle is already running.".to_string(), cycle_text));
    if wait && running_count() > 0 {
        log(&format!("waiting for {} response(s) to finish", running_count()));
        wait_running();
        // Fold their reports and waits into the cases now rather than at the next run.
        let merged = merge_now(config)?;
        out.push(format!("Responses finished: {} report(s) recorded.", merged.unwrap_or(0)));
        // A one-shot cycle (cron, by hand) sends the batch's results now rather than at its next run.
        let notify = notifier(config);
        let reported = with_lock(&config.state_dir, "cycle", || report_finished_batches(&config.state_dir, &notify, &iso(util::now()))).transpose()?;
        if let Some(reported) = reported.filter(|n| *n > 0) {
            out.push(format!("Batch report(s) sent: {reported}"));
        }
    }
    Ok(out.join("\n"))
}

/// The key of a case by its key or any alias (CVE, GHSA, ...).
fn find_case(cases: &IndexMap<String, Case>, key: Option<&str>) -> Result<String> {
    let Some(key) = key.filter(|k| !k.is_empty()) else { bail!("name the case: its key or a CVE/GHSA id (see status)") };
    if let Some(c) = cases.get(key) {
        return Ok(c.key.clone());
    }
    let lower = key.to_lowercase();
    match cases.values().find(|c| c.aliases.iter().any(|a| a == key) || c.key.to_lowercase() == lower) {
        Some(c) => Ok(c.key.clone()),
        None => bail!("no case {key} (status lists the open ones; cases.json in the state dir has all)"),
    }
}

/// Puts the cases whose last response did not finish on the retry queue (and takes finished ones off it), and says so
/// in the inbox. The caller holds the cycle lock.
fn queue_failures(config: &Config, cases: &IndexMap<String, Case>) -> Result<()> {
    let mut queue = retry::read(&config.state_dir);
    let absorbed = retry::absorb(&mut queue, &read_responses(&config.state_dir), cases, util::now());
    if !absorbed.queued.is_empty() {
        notifier(config)(&retry::queued_notice(&queue, cases, &absorbed.queued));
    }
    retry::write(&config.state_dir, &queue)
}

/// Folds finished responses into the cases now rather than at the next cycle. `None`: a cycle is running.
fn merge_now(config: &Config) -> Result<Option<usize>> {
    with_lock(&config.state_dir, "cycle", || -> Result<usize> {
        let mut cases: IndexMap<String, Case> = read_state(&config.state_dir, "cases.json").unwrap_or_default();
        let count = merge_responses(&config.state_dir, &mut cases, &iso(util::now()));
        write_state(&config.state_dir, "cases.json", &cases)?;
        queue_failures(config, &cases)?;
        Ok(count)
    })
    .transpose()
}

/// Runs the responder on one case now: a retry, a case below the notify floor, or a different mode the user chose.
fn respond_now(config: &Config, key: Option<&str>, mode_flag: Option<&str>) -> Result<String> {
    if config.responder.is_none() {
        bail!("no responder configured: add \"responder\" to the config");
    }
    let mode_flag = match mode_flag {
        None => None,
        Some("propose") => Some(Mode::Propose),
        Some("update") => Some(Mode::Update),
        Some("act") => Some(Mode::Act),
        Some(_) => bail!("--mode is propose, update or act"),
    };
    let started = with_lock(&config.state_dir, "cycle", || -> Result<(String, Mode, PathBuf)> {
        let dir = &config.state_dir;
        let mut cases: IndexMap<String, Case> = read_state(dir, "cases.json").unwrap_or_default();
        let Some(inventory) = read_state::<Inventory>(dir, "inventory.json") else { bail!("no inventory yet: run {NAME} inventory") };
        let key = find_case(&cases, key)?;
        let now = util::now();
        let mut c = cases[&key].clone();
        let prepared = prepare_case(config, &mut c, &inventory, &cases, now)?;
        let mode = mode_flag.unwrap_or(prepared.mode);
        if mode != prepared.mode {
            write_file_atomic(&prepared.file, &json_pretty(&case_file(config, &c, &inventory, &cases, mode, now))?)?;
        }
        with_deps(config, true, &Net, |deps| match deps.respond {
            Some(respond) => respond(&c, &prepared.file, mode, Run { batch: false, retry: false }),
            None => Err(anyhow!("no responder configured: add \"responder\" to the config")),
        })?;
        c.state = CaseState::Handled;
        c.handled_by = Some(HandledBy::Responder);
        c.handled_at = Some(iso(now));
        cases.insert(key.clone(), c);
        write_state(dir, "cases.json", &cases)?;
        Ok((key, mode, prepared.report))
    })
    .transpose()?;
    let Some((key, mode, report)) = started else { return Ok("A cycle is running; try again in a minute.".to_string()) };
    log(&format!("responder started on {key} ({}); waiting for it", mode.as_str()));
    wait_running();
    merge_now(config)?;
    Ok(format!("Response for {key} ({}) finished. Report: {}", mode.as_str(), report.display()))
}

/// Records a case the agent in charge handled in conversation, the way a responder's run is recorded.
fn record_report(config: &Config, key: Option<&str>, file: Option<&str>) -> Result<String> {
    let Some(file) = file else { bail!("--file REPORT: the report you wrote") };
    let text = redact(config, &fs::read_to_string(file).with_context(|| format!("read {file}"))?);
    let done = with_lock(&config.state_dir, "cycle", || -> Result<String> {
        let dir = &config.state_dir;
        let mut cases: IndexMap<String, Case> = read_state(dir, "cases.json").unwrap_or_default();
        let key = find_case(&cases, key)?;
        let now = util::now();
        let at = iso(now);
        // Its own file: a responder's report for the same case and day stays.
        let report = report_path(config, &key, now).to_string_lossy().into_owned();
        let report = match report.strip_suffix(".md") {
            Some(stem) => format!("{stem}-agent.md"),
            None => report,
        };
        fs::DirBuilder::new().recursive(true).mode(0o700).create(dir.join("reports"))?;
        write_file_atomic(Path::new(&report), &format!("{}\n", text.trim_end()))?;
        let waits = parse_waits(&text);
        let record = ResponseRecord {
            key: key.clone(),
            state: ResponseState::Done,
            started_at: at.clone(),
            finished_at: Some(at.clone()),
            report: Some(report.clone()),
            waits: Some(waits.clone()),
            triage: None,
            error: None,
            pid: None,
            urgent: Vec::new(),
        };
        write_state(dir, &format!("responses/{}.json", slug(&key)), &record)?;
        // The merge sets `report`, `handledAt` and the waits from the record.
        if let Some(c) = cases.get_mut(&key) {
            c.state = CaseState::Handled;
            c.handled_by = Some(HandledBy::Agent);
        }
        merge_responses(dir, &mut cases, &at);
        write_state(dir, "cases.json", &cases)?;
        queue_failures(config, &cases)?;
        let tracked = cases.get(&key).and_then(|c| c.waiting_for.as_deref()).unwrap_or_default();
        let describe = |waits: &[crate::fixes::FixWait]| waits.iter().map(describe_wait).collect::<Vec<_>>().join("; ");
        let or = |text: String, empty: &str| if text.is_empty() { empty.to_string() } else { text };
        Ok(format!(
            "Recorded {key}. Report: {report}\nFrom your report: {}\nThe watcher now checks {} wait(s): {}",
            or(describe(&waits), "no cvecondor-wait block"),
            tracked.len(),
            or(describe(tracked), "none")
        ))
    })
    .transpose()?;
    Ok(done.unwrap_or_else(|| "A cycle is running; try again in a minute.".to_string()))
}

/// Set by SIGTERM/SIGINT; the daemon finishes its cycle and stops.
static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_stop_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

fn daemon(config: &Config) -> Result<()> {
    log(&format!("{NAME} {VERSION}: every {} min, inventory every {} h, state {}", config.poll_minutes, config.inventory_hours, config.state_dir.display()));
    let handler = on_stop_signal as extern "C" fn(libc::c_int) as usize;
    // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
    unsafe {
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }
    relay::start(config, &STOP);
    while !STOP.load(Ordering::SeqCst) {
        match catch_unwind(AssertUnwindSafe(|| cycle(config, false, false))) {
            Ok(Ok(text)) => log(&text),
            Ok(Err(e)) => log(&format!("cycle failed: {}", redact(config, &format!("{e:#}")))),
            Err(_) => log("cycle failed: internal error (panic)"),
        }
        let until = Instant::now() + Duration::try_from_secs_f64(config.poll_minutes * 60.0).unwrap_or(Duration::from_secs(60));
        while !STOP.load(Ordering::SeqCst) && Instant::now() < until {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    relay::wait_idle();
    log("stopping after the current cycle");
    if running_count() > 0 {
        log(&format!("waiting for {} response(s)", running_count()));
        wait_running();
    }
    Ok(())
}

/// JS `Math.round`: halves go up.
fn round(x: f64) -> i64 {
    (x + 0.5).floor() as i64
}

fn ago(at: Option<&str>) -> String {
    let Some(at) = at.filter(|a| !a.is_empty()) else { return "never".to_string() };
    let Some(then) = parse_time(at) else { return "never".to_string() };
    let minutes = round((util::now().as_millisecond() - then.as_millisecond()) as f64 / 60_000.0);
    if minutes < 1 {
        "just now".to_string()
    } else if minutes < 120 {
        format!("{minutes} min ago")
    } else if minutes < 2880 {
        format!("{} h ago", round(minutes as f64 / 60.0))
    } else {
        format!("{} d ago", round(minutes as f64 / 1440.0))
    }
}

/// The first `n` characters.
fn clip(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

fn status(config: &Config) -> Result<String> {
    let dir = &config.state_dir;
    let feeds: IndexMap<String, FeedState> = read_state(dir, "feeds.json").unwrap_or_default();
    let inventory: Option<Inventory> = read_state(dir, "inventory.json");
    let last: Option<CycleSummary> = read_state(dir, "last-cycle.json");
    let cases: Vec<Case> = read_state::<IndexMap<String, Case>>(dir, "cases.json").unwrap_or_default().into_values().collect();
    let errors: Vec<(&String, &FeedState)> = feeds.iter().filter(|(_, f)| f.error.as_deref().is_some_and(|e| !e.is_empty())).collect();
    let mut open: Vec<&Case> = cases.iter().filter(|c| matches!(c.state, CaseState::Pending | CaseState::Judging | CaseState::Handled)).collect();
    open.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    let count = |state: CaseState| cases.iter().filter(|c| c.state == state).count();
    let classifier = match &config.classifier {
        Some(c) => format!("classifier.dev ({}, {})", c.model, if c.api_key.is_some() { "your key" } else { "anonymous free tier" }),
        None => "off (no key): prose advisories by name match only".to_string(),
    };
    let responder = match &config.responder {
        Some(r) => format!(
            "{}; fixes {}; works around on {}",
            r.agent.as_deref().or_else(|| r.command.for_mode(Mode::Propose).first().map(String::as_str)).unwrap_or(""),
            if r.update_when_fixed {
                format!("applied{}", if r.update_except.is_empty() { String::new() } else { format!(" except {}", r.update_except.join(", ")) })
            } else {
                "proposed".to_string()
            },
            if r.act_on.is_empty() { "nothing (proposes)".to_string() } else { r.act_on.join(", ") }
        ),
        None => "off (cases are notified directly)".to_string(),
    };
    let notifiers = config.notify.iter().map(|n| n.type_name()).collect::<Vec<_>>().join(", ");
    let rotation = match &config.rotation_map {
        Some(path) if path.exists() => {
            let keys = match serde_json::from_str::<serde_json::Value>(&fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?)
                .with_context(|| format!("parse {}", path.display()))?
            {
                serde_json::Value::Object(m) => m.len(),
                serde_json::Value::Array(a) => a.len(),
                _ => bail!("{}: not a JSON object", path.display()),
            };
            format!("{keys} keys ({})", path.display())
        }
        Some(path) => format!("MISSING {}", path.display()),
        None => "none".to_string(),
    };
    let runbooks = match &config.runbooks {
        Some(path) if path.exists() => {
            let n = fs::read_dir(path)?.filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().ends_with(".md")).count();
            format!("{n} ({})", path.display())
        }
        Some(path) => format!("MISSING {}", path.display()),
        None => "none".to_string(),
    };
    let mut lines = vec![
        format!("{NAME} {VERSION}. Config {}; state {}", config.file.display(), dir.display()),
        format!(
            "Classifier: {classifier}. Responder: {responder}. Notifiers: {}",
            if notifiers.is_empty() { "none (log only)".to_string() } else { notifiers }
        ),
        format!("Rotation map: {rotation}. Runbooks: {runbooks}"),
        format!(
            "Last cycle: {}",
            last.as_ref().map_or_else(
                || "none yet".to_string(),
                |l| format!("{} ({}), {} ms, {} polled, {} new", l.at, ago(Some(&l.at)), l.duration_ms, l.polled, l.fresh)
            )
        ),
    ];
    if let Some(l) = last.as_ref().filter(|l| !l.errors.is_empty()) {
        lines.push(format!("  errors: {}", l.errors.iter().take(6).cloned().collect::<Vec<_>>().join("; ")));
    }
    lines.push(inventory.as_ref().map_or_else(|| "Inventory: not collected yet".to_string(), inventory_text));
    lines.push(format!(
        "Sources: {} known, {} failing{}",
        feeds.len(),
        errors.len(),
        if errors.is_empty() {
            String::new()
        } else {
            format!(
                ": {}",
                errors
                    .iter()
                    .take(8)
                    .map(|(id, f)| format!("{id} ({}, last ok {})", f.error.as_deref().unwrap_or(""), ago(f.ok_at.as_deref())))
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        }
    ));
    let queue = retry::read(dir);
    if !queue.entries.is_empty() {
        let next = queue.entries.values().map(|e| e.next_at.as_str()).min().unwrap_or_default();
        let paused = queue.paused_until.as_deref().filter(|_| queue.paused(util::now())).map(|t| format!("; the agent is out of quota until {t}")).unwrap_or_default();
        lines.push(format!("Retry queue: {} case(s) waiting for another responder run, the next not before {next}{paused}", queue.entries.len()));
    }
    lines.push(format!("Open cases: {}", if open.is_empty() { "none".to_string() } else { open.len().to_string() }));
    for c in open.iter().take(25) {
        let tags = format!(
            "{}{}{}{}",
            c.assessment.as_ref().map(|a| format!("{}; ", a.rating.as_str())).unwrap_or_default(),
            c.severity.as_str(),
            if c.exploited == Some(true) { ", exploited" } else { "" },
            if c.priority == Some(true) { ", priority" } else { "" }
        );
        let handled = match c.handled_by {
            Some(by) => format!(
                " ({} {})",
                if by == HandledBy::Notice {
                    "notified".to_string()
                } else {
                    format!("by {}", serde_json::to_value(by).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default())
                },
                ago(c.handled_at.as_deref())
            ),
            None => String::new(),
        };
        lines.push(format!("  {} [{tags}] {}{handled}: {}", c.key, c.state.as_str(), clip(&c.title, 100)));
        lines.push(format!(
            "    {}{}{}{}",
            c.reason,
            c.waiting_for.as_deref().filter(|w| !w.is_empty()).map(|w| format!("; waiting for {} fix(es)", w.len())).unwrap_or_default(),
            c.report.as_deref().filter(|r| !r.is_empty()).map(|r| format!("; report {r}")).unwrap_or_default(),
            match queue.entries.get(&c.key) {
                Some(e) => format!("; queued to retry after {} (attempt {}): {}", e.next_at, e.attempts + 1, e.reason),
                None => c.dispatch_error.as_deref().filter(|e| !e.is_empty()).map(|e| format!("; dispatch failed: {e}")).unwrap_or_default(),
            }
        ));
    }
    lines.push(format!(
        "Recorded, not notified: {} below high, {} judged not affected, {} unsure (the install baseline's lower findings are in `baseline`, not cases)",
        count(CaseState::Watch),
        count(CaseState::NotAffected),
        count(CaseState::Unsure)
    ));
    lines.push(format!("Inbox: {} unread (`{NAME} inbox` shows them and marks them read)", unread(dir, false)?.len()));
    Ok(lines.join("\n"))
}

/// critical 0 … unknown 4: what comes first in a report.
fn severity_order(s: Severity) -> u8 {
    4 - s.rank()
}

/// Most urgent first.
fn rating_order(r: Rating) -> usize {
    match r {
        Rating::ActToday => 0,
        Rating::ActThisWeek => 1,
        Rating::PlanIt => 2,
        Rating::NotARealRisk => 3,
    }
}

/// One vulnerability in one place: GHSA, PYSEC and distro records of the same CVE merge into one row.
struct Row {
    severity: Severity,
    ids: IndexSet<String>,
    packages: IndexSet<String>,
    summary: String,
    fixes: IndexSet<String>,
    affected: Vec<Affected>,
    exploited: bool,
    malicious: bool,
}

/// What is already vulnerable or exposed: the install-time report the user sees instead of a silent baseline.
fn baseline(config: &Config) -> Result<String> {
    let dir = &config.state_dir;
    let inventory = match read_state::<Inventory>(dir, "inventory.json") {
        Some(i) => Some(i),
        None => refresh(config)?,
    };
    let Some(inventory) = inventory else { bail!("no inventory: run inventory first") };
    let mut families: Vec<String> = Vec::new();
    for family in inventory.items.iter().filter_map(|i| i.ecosystem.as_deref()).map(osv_family) {
        if !families.iter().any(|f| f == family) {
            families.push(family.to_string());
        }
    }
    let hits = osv_query(&inventory, &families, &Net)?;
    let mut records: IndexMap<String, OsvRecord> = read_state(dir, "osv-records.json").unwrap_or_default();
    let list: Vec<_> = hits.values().collect();
    let stale: Vec<_> = list.iter().filter(|hit| records.get(&hit.id).is_none_or(|r| r.modified != hit.modified)).collect();
    // A record that cannot be fetched is counted as unknown severity.
    let fetched = util::parallel_map(&stale, 8, |hit| osv_record(&hit.id, &Net));
    for (hit, r) in stale.iter().zip(fetched).filter_map(|(hit, r)| Some((hit, r.ok()?))) {
        records.insert(
            hit.id.clone(),
            OsvRecord {
                id: r.id,
                modified: r.modified,
                aliases: r.aliases,
                summary: r.summary,
                severity: r.severity,
                database_specific: r.database_specific,
                affected: r
                    .affected
                    .map(|a| a.into_iter().map(|a| crate::matching::OsvAffected { package: a.package, ranges: a.ranges, ..Default::default() }).collect()),
                ..OsvRecord::default()
            },
        );
    }
    write_state(dir, "osv-records.json", &records)?;
    // One row per vulnerability per place: GHSA, PYSEC and distro records of the same CVE merge.
    let kev: HashSet<String> = read_state::<IndexMap<String, FeedState>>(dir, "feeds.json")
        .and_then(|mut feeds| feeds.swap_remove("cisa-kev"))
        .and_then(|f| f.seen)
        .map(|seen| seen.into_keys().collect())
        .unwrap_or_default();
    let place_of = |i: &InventoryItem| format!("{} {}", i.host, i.r#where);
    let mut by_place: IndexMap<String, IndexMap<String, Row>> = IndexMap::new();
    for hit in &list {
        let record = records.get(&hit.id);
        let severity = record.map_or(Severity::Unknown, osv_severity);
        let aliases: Vec<&str> =
            std::iter::once(hit.id.as_str()).chain(record.and_then(|r| r.aliases.as_deref()).unwrap_or_default().iter().map(String::as_str)).collect();
        let key = aliases.iter().find(|a| a.starts_with("CVE-")).copied().unwrap_or(&hit.id).to_string();
        let places: IndexSet<String> = hit.items.iter().map(place_of).collect();
        for place in places {
            let items: Vec<InventoryItem> = hit.items.iter().filter(|i| place_of(i) == place).cloned().collect();
            let rows = by_place.entry(place).or_default();
            let row = rows.entry(key.clone()).or_insert_with(|| Row {
                severity,
                ids: IndexSet::new(),
                packages: IndexSet::new(),
                summary: String::new(),
                fixes: IndexSet::new(),
                affected: Vec::new(),
                exploited: false,
                malicious: false,
            });
            if severity_order(severity) < severity_order(row.severity) {
                row.severity = severity;
            }
            row.ids.insert(hit.id.clone());
            row.exploited |= aliases.iter().any(|a| kev.contains(*a));
            row.malicious |= hit.id.starts_with("MAL-");
            for i in &items {
                row.packages.insert(format!("{} {}", i.name, i.version));
                row.affected.push(Affected {
                    host: i.host.clone(),
                    r#where: i.r#where.clone(),
                    name: i.name.clone(),
                    version: i.version.clone(),
                    running: i.running,
                    dev: i.dev,
                });
            }
            if row.summary.is_empty() {
                row.summary = record.and_then(|r| r.summary.clone()).unwrap_or_default();
            }
            if let Some(record) = record {
                for f in osv_fixes(record, &items) {
                    if !(f.len() == 40 && f.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))) {
                        row.fixes.insert(f);
                    }
                }
            }
        }
    }
    // Exploited first, then by how serious it is for this user, then by severity.
    struct Place<'a> {
        place: &'a str,
        top: Assessment,
        lower: usize,
        exploited: usize,
        rows: Vec<String>,
    }
    let secrets_at = |place: &str| inventory.secrets.iter().filter(|s| format!("{} {}", s.host, s.r#where) == place).count();
    let mut places: Vec<Place> = Vec::new();
    for (place, rows) in &by_place {
        let mut all: Vec<(&String, &Row, Assessment)> = rows
            .iter()
            .map(|(key, r)| {
                let a = assess(&AssessInput {
                    severity: r.severity,
                    exploited: r.exploited,
                    malicious: r.malicious,
                    affected: &r.affected,
                    inventory: &inventory,
                    at_risk: secrets_at(place),
                });
                (key, r, a)
            })
            .collect();
        all.sort_by(|(_, x, xa), (_, y, ya)| {
            y.exploited
                .cmp(&x.exploited)
                .then(rating_order(xa.rating).cmp(&rating_order(ya.rating)))
                .then(severity_order(x.severity).cmp(&severity_order(y.severity)))
        });
        let shown: Vec<_> = all.iter().filter(|(_, r, _)| r.severity.rank() >= Severity::High.rank() || r.exploited || r.malicious).collect();
        let Some((_, _, top)) = shown.first() else { continue };
        places.push(Place {
            place,
            top: top.clone(),
            lower: all.len() - shown.len(),
            exploited: shown.iter().filter(|(_, r, _)| r.exploited).count(),
            rows: shown
                .iter()
                .map(|(key, r, a)| {
                    format!(
                        "**{}** {}{} {key}{}: {}{}{}",
                        a.rating.as_str(),
                        r.severity.as_str().to_uppercase(),
                        if r.exploited { " EXPLOITED" } else { "" },
                        if r.ids.contains(key.as_str()) { String::new() } else { format!(" ({})", r.ids.iter().cloned().collect::<Vec<_>>().join(", ")) },
                        r.packages.iter().cloned().collect::<Vec<_>>().join(", "),
                        if r.summary.is_empty() { String::new() } else { format!(": {}", clip(&r.summary, 90)) },
                        if r.fixes.is_empty() {
                            "; no fix yet".to_string()
                        } else {
                            format!("; fixed in {}", r.fixes.iter().cloned().collect::<Vec<_>>().join(" / "))
                        }
                    )
                })
                .collect(),
        });
    }
    places
        .sort_by(|a, b| b.exploited.cmp(&a.exploited).then(rating_order(a.top.rating).cmp(&rating_order(b.top.rating))).then(b.rows.len().cmp(&a.rows.len())));
    let secrets: Vec<_> = inventory.secrets.iter().filter(|s| s.exposure != Exposure::ContainerEnv && s.exposure != Exposure::CiSecret).collect();
    let kept = inventory.secrets.len() - secrets.len();
    let vendors = detect_vendors(&inventory, config);
    let mut out = vec![
        "# Baseline: what is vulnerable or exposed today".to_string(),
        String::new(),
        format!(
            "Inventory {}: {} items from {}. {} known advisories match. Below: critical, high and exploited ones per place, each rated for you (act today, act this week, plan it, not a real risk for you) with why. Exploited ones get the normal response; the rest are assessed and proposed, not acted on.",
            inventory.collected_at,
            inventory.items.len(),
            inventory.sources.keys().cloned().collect::<Vec<_>>().join(", "),
            list.len()
        ),
        String::new(),
    ];
    for p in &places {
        out.push(format!("## {}: {}", p.place, p.top.rating.as_str()));
        out.push(String::new());
        out.push(format!("Why: {}", p.top.why));
        out.push(String::new());
        out.extend(p.rows.iter().map(|r| format!("- {r}")));
        if p.lower > 0 {
            out.push(format!("- ({} medium/low/unscored recorded)", p.lower));
        }
        out.push(String::new());
    }
    if places.is_empty() {
        out.push("No critical or high advisories match what you run.".to_string());
        out.push(String::new());
    }
    out.push(format!("## Secrets where they shouldn't be ({})", secrets.len()));
    out.push(String::new());
    if secrets.is_empty() {
        out.push("None found.".to_string());
    } else {
        out.extend(secrets.iter().map(|s| format!("- {}: {}", describe_secret(s), s.risk)));
    }
    out.push(String::new());
    if kept > 0 {
        out.push(format!(
            "{kept} more secret(s) live in container environments or CI secrets, where they belong; they are kept (names and fingerprints) so a breach shows what to rotate."
        ));
        out.push(String::new());
    }
    out.push(format!("## Vendors watched ({})", vendors.len()));
    out.push(String::new());
    out.extend(vendors.iter().map(|v| {
        format!(
            "- {}{}: {}",
            v.name,
            if v.feeds.is_empty() { " (no incident feed: news only)" } else { "" },
            v.evidence.iter().take(3).cloned().collect::<Vec<_>>().join("; ")
        )
    }));
    out.push(String::new());
    Ok(out.join("\n"))
}

/// A directory only this user can enter, unique per call.
fn temp_dir() -> Result<PathBuf> {
    let base = std::env::temp_dir();
    for attempt in 0..100u32 {
        let nanos = util::now().as_nanosecond();
        let dir = base.join(format!("{NAME}-replay-{}-{nanos:x}-{attempt}", std::process::id()));
        match fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).with_context(|| format!("create {}", dir.display())),
        }
    }
    bail!("could not create a temporary directory under {}", base.display())
}

fn replay(config: &Config, opts: &Opts) -> Result<String> {
    let sources = || SOURCES.iter().chain(NEWS_SOURCES.iter());
    let source = sources().find(|s| Some(s.id.as_str()) == opts.source.as_deref()).filter(|s| !matches!(s.kind, SourceKind::OsvHead | SourceKind::CveList));
    let Some(source) = source else {
        bail!(
            "--source must be one of {}",
            sources().filter(|s| !matches!(s.kind, SourceKind::OsvHead | SourceKind::CveList)).map(|s| s.id.as_str()).collect::<Vec<_>>().join(", ")
        )
    };
    let inventory = match &opts.inventory {
        Some(file) => serde_json::from_str::<Inventory>(&fs::read_to_string(file).with_context(|| format!("read {file}"))?).with_context(|| format!("parse {file}"))?,
        None => read_state::<Inventory>(&config.state_dir, "inventory.json").ok_or_else(|| anyhow!("no inventory yet: run {NAME} inventory (or pass --inventory FILE)"))?,
    };
    let mut body = match &opts.file {
        Some(file) => fs::read_to_string(file).with_context(|| format!("read {file}"))?,
        None => Net.fetch(Request::get(&source.url).timeout(Duration::from_secs(60)))?.text(),
    };
    if let Some(only) = &opts.only {
        let needle = only.to_lowercase();
        let blocks = Regex::new(r"(?i)<item\b[\s\S]*?</item>|<entry\b[\s\S]*?</entry>")?;
        body =
            blocks.replace_all(&body, |m: &regex::Captures| if m[0].to_lowercase().contains(&needle) { m[0].to_string() } else { String::new() }).into_owned();
    }
    let dir = temp_dir()?;
    let scratch = Config { state_dir: dir.clone(), ..config.clone() };
    let run = || -> Result<String> {
        write_state(&dir, "inventory.json", &inventory)?;
        // A second ago, so the cycle's own time (which marks the sources it polled) never equals it: a fast machine
        // would otherwise count every source as polled.
        let now = iso(Timestamp::from_millisecond(util::now().as_millisecond() - 1000)?);
        // Every other source counts as just polled and OSV as just queried: only the replayed document is new.
        let mut feeds: IndexMap<String, FeedState> = sources()
            .map(|s| {
                (
                    s.id.clone(),
                    FeedState {
                        polled_at: Some(now.clone()),
                        ok_at: Some(now.clone()),
                        baselined: Some(true),
                        cursor: Some("9999".to_string()),
                        ..FeedState::default()
                    },
                )
            })
            .collect();
        feeds.insert(source.id.clone(), FeedState { baselined: Some(true), seen: Some(IndexMap::new()), ..FeedState::default() });
        write_state(&dir, "feeds.json", &feeds)?;
        let mut families: IndexSet<String> = IndexSet::new();
        families.extend(inventory.items.iter().filter_map(|i| i.ecosystem.as_deref()).map(|e| osv_family(e).to_string()));
        let known = Known {
            osv_queried_at: families.into_iter().map(|f| (f, now.clone())).collect(),
            secrets: Some(inventory.secrets.iter().map(|_| String::new()).collect()),
            node_index: (source.kind == SourceKind::NodeIndex).then(Vec::new),
            ..Known::default()
        };
        write_state(&dir, "known.json", &known)?;
        let url = source.url.clone();
        let fetch = |req: Request| -> Result<Response> {
            if req.url == url { Ok(Response { status: 200, headers: Vec::new(), body: body.clone().into_bytes() }) } else { Net.fetch(req) }
        };
        let summary = with_deps(&scratch, opts.respond, &fetch, |deps| run_cycle(&scratch, deps))?;
        if opts.respond {
            wait_running();
        }
        let cases: Vec<Case> = read_state::<IndexMap<String, Case>>(&dir, "cases.json").unwrap_or_default().into_values().collect();
        let mut out = vec![format!(
            "Replay of {} against the inventory of {} ({} items): {} new item(s), {} case(s)",
            source.id,
            inventory.collected_at,
            inventory.items.len(),
            summary.fresh,
            cases.len()
        )];
        for c in &cases {
            out.push(String::new());
            out.push(format!("{}: {} [{}] {}", c.key, c.state.as_str(), c.severity.as_str(), c.title));
            out.push(format!("  {}", c.reason));
            if !c.aliases.is_empty() {
                out.push(format!("  ids: {}", c.aliases.join(", ")));
            }
            if let Some(published) = c.items.as_deref().unwrap_or_default().iter().find_map(|i| i.published.as_deref()) {
                out.push(format!("  published: {published}; the case opens at the next poll (every {} min)", config.poll_minutes));
            }
            out.push(format!("  fix: {}", if c.fix_available { "a fixed release exists" } else { "none released yet" }));
            if let Some(a) = &c.assessment {
                out.push(format!("  rating: {}: {}", a.rating.as_str(), a.why));
            }
            if config.responder.is_some() {
                out.push(format!("  your agent would run in {} mode", case_mode(config, c, &inventory).as_str()));
            }
            if let Some(at_risk) = c.at_risk.as_deref().filter(|a| !a.is_empty()) {
                out.push(format!("  stored at the affected places: {}", at_risk.join("; ")));
            }
            out.extend(c.targets.iter().take(40).map(|t| format!("  - {t}")));
        }
        if cases.is_empty() {
            out.push(String::new());
            out.push("No case: nothing in the replayed document names what you run.".to_string());
        }
        if opts.respond {
            out.push(String::new());
            out.push(format!("Replay state (case files, reports): {}", dir.display()));
        }
        Ok(out.join("\n"))
    };
    let result = run();
    if !opts.respond {
        let _ = fs::remove_dir_all(&dir);
    }
    result
}

/// The vendors in the shipped catalogue matching a term (all of them without one).
fn catalog_text(term: &str) -> String {
    let term = term.to_lowercase();
    let lines: Vec<String> = VENDORS
        .iter()
        .filter(|v| term.is_empty() || v.id.contains(&term) || v.name.to_lowercase().contains(&term) || v.aliases.iter().any(|a| a.contains(&term)))
        .map(|v| {
            let mut kinds: Vec<&str> = Vec::new();
            for f in &v.feeds {
                if !kinds.contains(&f.kind.as_str()) {
                    kinds.push(f.kind.as_str());
                }
            }
            let feeds = if v.feeds.is_empty() { "  (no feed: news only)".to_string() } else { format!("  ({} feed)", kinds.join(", ")) };
            format!("{:<22} {}{feeds}", v.id, v.name)
        })
        .collect();
    if lines.is_empty() { "No catalogue vendor matches.".to_string() } else { lines.join("\n") }
}

#[derive(Default)]
struct Opts {
    config: Option<String>,
    out: Option<String>,
    source: Option<String>,
    file: Option<String>,
    only: Option<String>,
    respond: bool,
    inventory: Option<String>,
    no_wait: bool,
    catalog: bool,
    mode: Option<String>,
    all: bool,
    peek: bool,
    once: bool,
    test: bool,
    help: bool,
    version: bool,
}

fn parse_args(args: Vec<OsString>) -> Result<(Opts, Vec<String>)> {
    use lexopt::prelude::*;
    let mut opts = Opts::default();
    let mut positionals = Vec::new();
    let mut parser = lexopt::Parser::from_args(args);
    while let Some(arg) = parser.next()? {
        match arg {
            Long("config") => opts.config = Some(parser.value()?.string()?),
            Long("out") => opts.out = Some(parser.value()?.string()?),
            Long("source") => opts.source = Some(parser.value()?.string()?),
            Long("file") => opts.file = Some(parser.value()?.string()?),
            Long("only") => opts.only = Some(parser.value()?.string()?),
            Long("inventory") => opts.inventory = Some(parser.value()?.string()?),
            Long("mode") => opts.mode = Some(parser.value()?.string()?),
            Long("respond") => opts.respond = true,
            Long("no-wait") => opts.no_wait = true,
            Long("catalog") => opts.catalog = true,
            Long("all") => opts.all = true,
            Long("peek") => opts.peek = true,
            Long("once") => opts.once = true,
            Long("test") => opts.test = true,
            Long("help") | Short('h') => opts.help = true,
            Long("version") => opts.version = true,
            Value(v) => positionals.push(v.string()?),
            _ => return Err(arg.unexpected().into()),
        }
    }
    Ok((opts, positionals))
}

/// `Ok(exit code)`; an `Err` is printed by `main` and exits 1.
fn run(args: Vec<OsString>) -> Result<i32> {
    let (opts, positionals) = parse_args(args)?;
    let command = positionals.first().map(String::as_str);
    if opts.version {
        say(&format!("{NAME} {VERSION}"));
        return Ok(0);
    }
    let Some(command) = command.filter(|_| !opts.help) else {
        say(&help());
        return Ok(0);
    };
    // The catalogue is shipped data: searchable before any config exists (the installer needs it first).
    if command == "vendors" && opts.catalog {
        say(&catalog_text(positionals.get(1).map_or("", String::as_str)));
        return Ok(0);
    }
    // Follow runs on the user's own machine, usually without a watcher config: it has its own (follow.json).
    if command == "follow" {
        return crate::follow::run(opts.config.as_deref(), opts.once, opts.test);
    }
    let env = process_env();
    let config = load_config(opts.config.as_deref(), &env)?;
    // As Node's `process.loadEnvFile`: the env file's variables reach every child (a command notifier, ssh, gitleaks).
    // The responder's environment still drops them (`secret_env`).
    let from_file: std::collections::HashMap<String, String> = load_env_file(&config.file).unwrap_or_default().into_iter().collect();
    for (name, value) in from_file {
        if std::env::var_os(&name).is_none() {
            // SAFETY: start-up, before this process spawns any thread.
            unsafe { std::env::set_var(&name, &value) };
        }
    }
    fs::DirBuilder::new().recursive(true).mode(0o700).create(&config.state_dir).with_context(|| format!("create {}", config.state_dir.display()))?;
    let write = |text: &str| -> Result<()> {
        match &opts.out {
            Some(out) => {
                write_private(Path::new(out), &format!("{text}\n"))?;
                say(&format!("wrote {out}"));
            }
            None => say(text),
        }
        Ok(())
    };
    let need_inventory = || read_state::<Inventory>(&config.state_dir, "inventory.json").ok_or_else(|| anyhow!("no inventory yet: run {NAME} inventory"));
    match command {
        "run" => daemon(&config)?,
        "cycle" => {
            let mut text = cycle(&config, !opts.no_wait, false)?;
            // A one-shot run answers the user's Telegram messages too, once (the daemon has its own relay thread).
            if let Some(replies) = relay::poll_cycle(&config) {
                text.push('\n');
                text.push_str(&replies);
            }
            say(&text);
        }
        "inventory" => match refresh(&config)? {
            None => say("An inventory refresh is already running."),
            Some(inventory) => {
                if let Some(out) = &opts.out {
                    write_private(Path::new(out), &json_pretty(&inventory)?)?;
                }
                say(&inventory_text(&inventory));
                // Every collector failing means nothing was read: a script checking the exit code must see that.
                if !inventory.sources.is_empty() && inventory.sources.values().all(|s| !s.ok) {
                    return Ok(1);
                }
            }
        },
        "baseline" => write(&baseline(&config)?)?,
        "status" => say(&status(&config)?),
        "inbox" => {
            let entries = unread(&config.state_dir, opts.all)?;
            if let (Some(last), false) = (entries.last(), opts.peek) {
                mark_read(&config.state_dir, &last.at)?;
            }
            let text = entries.iter().map(|e| format!("{} [{}] {}\n  {}", e.at, e.event, e.title, e.file)).collect::<Vec<_>>().join("\n");
            say(if text.is_empty() { "Nothing new." } else { &text });
        }
        "vendors" => {
            let inventory = need_inventory()?;
            let text = detect_vendors(&inventory, &config)
                .iter()
                .map(|v| {
                    let feeds = v.feeds.iter().map(|f| format!("{} {}", f.kind.as_str(), f.url)).collect::<Vec<_>>().join(", ");
                    format!(
                        "{} ({}){}\n  evidence: {}\n  feeds: {}",
                        v.id,
                        v.name,
                        if v.manual { " [config]" } else { "" },
                        v.evidence.iter().take(6).cloned().collect::<Vec<_>>().join("; "),
                        if feeds.is_empty() { "none (news only)" } else { &feeds }
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            say(if text.is_empty() { "No vendors detected." } else { &text });
        }
        "secrets" => {
            let inventory = need_inventory()?;
            let text = inventory.secrets.iter().map(|s| format!("{}\n  {}", describe_secret(s), s.risk)).collect::<Vec<_>>().join("\n");
            say(if text.is_empty() { "No secret findings." } else { &text });
        }
        "notify-test" => {
            let host = env.get("HOSTNAME").map_or("this machine", String::as_str);
            let notice = Notice {
                event: NotifyEvent::Test,
                title: format!("[{NAME}] test notice from {host}: notifications work. Only urgent things come here, one line each."),
                text: String::new(),
                key: None,
                severity: None,
                urls: None,
                report_path: None,
            };
            let result = send_notice(&config, &notice, &Net, util::now());
            let sent = if result.sent.is_empty() { "none".to_string() } else { result.sent.join(", ") };
            let errors = if result.errors.is_empty() { String::new() } else { format!("\nerrors:\n  {}", result.errors.join("\n  ")) };
            say(&format!("sent: {sent}{errors}"));
        }
        "replay" => say(&replay(&config, &opts)?),
        "respond" => say(&respond_now(&config, positionals.get(1).map(String::as_str), opts.mode.as_deref())?),
        "record" => say(&record_report(&config, positionals.get(1).map(String::as_str), opts.file.as_deref())?),
        _ => {
            say(&help());
            return Ok(2);
        }
    }
    Ok(0)
}

/// Runs the command line and returns the process exit code.
pub fn main() -> i32 {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match run(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{e:#}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ago_rounds_like_the_original_and_never_says_never_for_a_real_time() {
        let at = |minutes: i64| iso(Timestamp::from_millisecond(util::now().as_millisecond() - minutes * 60_000).expect("a valid time"));
        assert_eq!(ago(None), "never");
        assert_eq!(ago(Some(&at(0))), "just now");
        assert_eq!(ago(Some(&at(119))), "119 min ago");
        assert_eq!(ago(Some(&at(120))), "2 h ago");
        assert_eq!(ago(Some(&at(2880))), "2 d ago");
    }
}

#[cfg(test)]
mod replay_tests {
    use super::*;

    fn run_replay(source: &str, file: &str) -> String {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let state = temp_dir().expect("a temp dir");
        let env: crate::config::Env = [("CVECONDOR_STATE_DIR".to_string(), state.display().to_string())].into();
        let config = load_config(Some(&root.join("examples/replay/config.json").display().to_string()), &env).expect("the example config loads");
        let opts = Opts {
            source: Some(source.into()),
            file: Some(root.join("tests/fixtures").join(file).display().to_string()),
            inventory: Some(root.join("examples/replay/inventory.json").display().to_string()),
            ..Opts::default()
        };
        let out = replay(&config, &opts).expect("the replay runs");
        let _ = fs::remove_dir_all(&state);
        out
    }

    #[test]
    fn the_php_advisory_on_the_example_stack_is_rated_act_today_and_updated_by_the_agent() {
        let out = run_replay("cert-eu", "cert-eu-2026-10-21.xml");
        assert!(out.contains("2026-018: Critical Vulnerabilities in PHP"), "{out}");
        assert!(out.contains("rating: act today: critical and publicly reachable at blog.example.com"), "{out}");
        assert!(out.contains("fix: a fixed release exists"), "{out}");
        assert!(out.contains("your agent would run in update mode"), "{out}");
        assert!(out.contains("web1 container:old-shop php 8.2.20 (stopped)"), "{out}");
    }

    #[test]
    fn a_ca_incident_without_a_fixed_release_is_proposed_not_updated() {
        let out = run_replay("ca-incidents", "bugzilla-ca-2083449.json");
        assert!(out.contains("fix: none released yet"), "{out}");
        assert!(out.contains("your agent would run in propose mode"), "{out}");
    }

    #[test]
    fn a_document_that_names_nothing_you_run_opens_no_case() {
        let out = run_replay("nginx-news", "nginx-news-2026-10-14.xml");
        assert!(out.contains("0 case(s)") && out.contains("No case:"), "{out}");
    }
}
