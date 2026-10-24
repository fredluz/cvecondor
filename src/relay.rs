// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! The user answers CVECondor's Telegram messages. A telegram notifier with `"replies": true` makes the watcher read
//! its own bot's messages (`getUpdates`; CVECondor is the bot's only reader), from the configured chat only, hand each
//! text plus the last few urgent lines it sent to the agent in charge (the responder's `act` command, run headless),
//! and send the agent's answer back to the chat. Nothing more: the agent itself does whatever the user asked (merge or
//! close a PR with `gh`, say), under the rules in AGENTS.md, which is compiled in and is the start of every prompt.
//!
//! The daemon runs one polling thread per such notifier (`start`); the one-shot `cycle` command does one non-waiting
//! poll at its end (`poll_cycle`), so cron and Action setups answer too. The offset (the last update id + 1) is kept in
//! the state dir and written before a batch is handled: a crash never replays a message, and a one-shot run never
//! handles one twice.

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use indexmap::IndexMap;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config::{Config, Env, Mode, NotifierConfig, NotifierKind, NotifyEvent, process_env, redact};
use crate::http::{Fetch, Net, Request};
use crate::inbox::{keep, unread};
use crate::name::{ENV_PREFIX, USER_AGENT};
use crate::notify::Notice;
use crate::responder::{responder_command, responder_env};
use crate::retry::{self, Queue};
use crate::state::{read_state, with_lock, write_file_atomic, write_state};
use crate::util::{self, RunOptions, iso, sha256_hex};

/// The rules the agent in charge works under; the start of every prompt.
const AGENTS_MD: &str = include_str!("../AGENTS.md");
const API: &str = "https://api.telegram.org";
/// Telegram holds a `getUpdates` request this long when nothing is waiting.
const LONG_POLL_SECONDS: u64 = 50;
/// Over the long poll, so a quiet bot is not a transport error.
const POLL_SLACK: Duration = Duration::from_secs(20);
const SEND_TIMEOUT: Duration = Duration::from_secs(20);
const AGENT_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const ERROR_BACKOFF: Duration = Duration::from_secs(30);
const CONFLICT_BACKOFF: Duration = Duration::from_secs(5 * 60);
/// What goes back to the chat: at most this many characters.
const REPLY_MAX: usize = 1000;
/// How many of the last urgent lines the agent is told about.
const URGENT_LINES: usize = 5;
/// How much of their text titles the inbox entry of an exchange.
const TITLE_CHARS: usize = 80;

/// Telegram answered 409: another `getUpdates` reader, or a webhook, holds this bot.
#[derive(Debug)]
pub struct Conflict;

impl std::fmt::Display for Conflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("this bot has another getUpdates reader or a webhook; replies need a bot of its own")
    }
}

impl std::error::Error for Conflict {}

/// Everything the agent runner needs for one message.
#[derive(Debug, Clone)]
pub struct RelayJob {
    /// What the user wrote.
    pub text: String,
    /// The text of the message they replied to, if it was a reply.
    pub reply_to: Option<String>,
    /// The full prompt (also written to `<workdir>/prompt.md`).
    pub prompt: String,
    /// `<stateDir>/work/relay-<yyyymmddhhmmss>/`: `prompt.md`, `AGENTS.md`, and where the agent writes `reply.md`.
    pub workdir: PathBuf,
    /// The responder's `act` argv with its placeholders replaced.
    pub argv: Vec<String>,
    /// The prompt goes on stdin (no argument had `{prompt}`).
    pub stdin: bool,
    /// Exactly the child's environment.
    pub env: Vec<(String, String)>,
    pub cwd: PathBuf,
    pub timeout: Duration,
}

/// How a poll runs; `Default` is the daemon's (long poll, the real environment, `util::log`).
pub struct PollOptions<'a> {
    /// The environment the agent's is derived from. `None`: the process's.
    pub env: Option<&'a Env>,
    /// `getUpdates` `timeout`: 0 returns at once (one-shot cycle).
    pub wait_seconds: u64,
    /// Where `relay: …` lines go. `None`: `util::log`.
    pub log: Option<&'a (dyn Fn(&str) + Sync)>,
    /// When set, a batch that arrives after it is left unread for the next start.
    pub stop: Option<&'a AtomicBool>,
}

impl Default for PollOptions<'_> {
    fn default() -> Self {
        Self { env: None, wait_seconds: LONG_POLL_SECONDS, log: None, stop: None }
    }
}

impl PollOptions<'_> {
    fn say(&self, line: &str) {
        match self.log {
            Some(log) => log(line),
            None => util::log(line),
        }
    }
}

/// Messages being handled right now: a stopping daemon waits for them (`wait_idle`).
static BUSY: AtomicUsize = AtomicUsize::new(0);

struct Busy;

impl Busy {
    fn enter() -> Self {
        BUSY.fetch_add(1, Ordering::SeqCst);
        Busy
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        BUSY.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Blocks until no message is being handled (an agent run is at most 15 minutes).
pub fn wait_idle() {
    if BUSY.load(Ordering::SeqCst) > 0 {
        util::log("relay: waiting for the agent to answer");
    }
    while BUSY.load(Ordering::SeqCst) > 0 {
        thread::sleep(Duration::from_millis(200));
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Offset {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    offset: Option<i64>,
}

/// A chat that wrote to the bot, as Telegram describes it. Names only: never what was written.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Chat {
    pub id: i64,
    /// `private`, `group`, `supergroup` or `channel`.
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
}

impl Chat {
    /// `private chat with Ana Silva (@ana)` / `group "Ops"`: how the user would recognise it.
    pub fn describe(&self) -> String {
        let name = match (&self.title, &self.first_name, &self.last_name) {
            (Some(title), _, _) => format!("\"{title}\""),
            (None, Some(first), Some(last)) => format!("{first} {last}"),
            (None, Some(first), None) => first.clone(),
            _ => String::new(),
        };
        let at = self.username.as_deref().map(|u| format!("@{u}")).unwrap_or_default();
        let who = [name, at].iter().filter(|s| !s.is_empty()).cloned().collect::<Vec<_>>().join(" ");
        let kind = if self.kind.is_empty() { "chat" } else { &self.kind };
        if who.is_empty() { kind.to_string() } else { format!("{kind}: {who}") }
    }
}

/// The chat of an update, whatever kind of update it is (`message`, `my_chat_member`, ...).
pub fn chat_of(update: &Value) -> Option<Chat> {
    let chat = update.as_object()?.iter().filter(|(key, _)| key.as_str() != "update_id").find_map(|(_, v)| v.get("chat"))?;
    let text = |key: &str| chat.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);
    Some(Chat {
        id: chat.get("id")?.as_i64()?,
        kind: text("type").unwrap_or_default(),
        title: text("title"),
        username: text("username"),
        first_name: text("first_name"),
        last_name: text("last_name"),
    })
}

/// What the relay keeps for one bot beside its offset, for `status` and `telegram-chat`: when it last read, how it
/// is failing, whether it is answering a message, and who wrote to the bot.
#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Seen {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    polled_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    handling_since: Option<String>,
    #[serde(default)]
    chats: IndexMap<String, Chat>,
}

/// `relay-<first 8 hex of sha256(token)>-seen.json`.
fn seen_file(token: &str) -> String {
    format!("relay-{}-seen.json", &sha256_hex(token.as_bytes())[..8])
}

fn update_seen(config: &Config, token: &str, change: impl FnOnce(&mut Seen)) {
    let file = seen_file(token);
    let mut seen: Seen = read_state(&config.state_dir, &file).unwrap_or_default();
    change(&mut seen);
    if let Err(e) = write_state(&config.state_dir, &file, &seen) {
        util::log(&format!("relay: could not keep its status: {}", scrub(config, token, &format!("{e:#}"))));
    }
}

/// A poll came back: the relay is reading, and these chats wrote to the bot.
fn note_poll(config: &Config, token: &str, at: Timestamp, chats: &[Chat]) {
    update_seen(config, token, |seen| {
        seen.polled_at = Some(iso(at));
        seen.error = None;
        for chat in chats {
            seen.chats.insert(chat.id.to_string(), chat.clone());
        }
    });
}

/// A poll failed: `status` says why, until the next one succeeds.
fn note_error(config: &Config, token: &str, error: &str) {
    update_seen(config, token, |seen| seen.error = Some(error.to_string()));
}

fn note_handling(config: &Config, token: &str, since: Option<Timestamp>) {
    update_seen(config, token, |seen| seen.handling_since = since.map(iso));
}

/// Clears "answering a message" however the batch ends.
struct Handling<'a> {
    config: &'a Config,
    token: &'a str,
}

impl Drop for Handling<'_> {
    fn drop(&mut self) {
        note_handling(self.config, self.token, None);
    }
}

/// The chats the relay has seen writing to the bot of `token`, oldest first.
pub fn seen_chats(state_dir: &Path, token: &str) -> Vec<Chat> {
    read_state::<Seen>(state_dir, &seen_file(token)).map(|s| s.chats.into_values().collect()).unwrap_or_default()
}

/// A poll this recent means a daemon is reading now (a long poll lasts `LONG_POLL_SECONDS`).
const READING_SECONDS: i64 = 150;

fn short_ago(seconds: i64) -> String {
    match seconds {
        s if s < 120 => format!("{} s", s.max(0)),
        s if s < 7200 => format!("{} min", s / 60),
        s if s < 172_800 => format!("{} h", s / 3600),
        s => format!("{} d", s / 86_400),
    }
}

/// The reply part of a notifier's line in `status`: `None` for a notifier that is not Telegram.
pub fn status_text(config: &Config, notifier: &NotifierConfig, now: Timestamp) -> Option<String> {
    let NotifierKind::Telegram { bot_token, replies, .. } = &notifier.kind else { return None };
    if !replies {
        return Some("replies off (urgent lines only go out)".to_string());
    }
    let seen: Seen = read_state(&config.state_dir, &seen_file(bot_token)).unwrap_or_default();
    let since = |at: &Option<String>| at.as_deref().and_then(util::parse_time).map(|t| now.as_second() - t.as_second());
    let age = since(&seen.polled_at);
    let busy = since(&seen.handling_since).filter(|s| *s < AGENT_TIMEOUT.as_secs() as i64 + 60);
    Some(if let Some(error) = &seen.error {
        format!("replies on, FAILING: {error}")
    } else if busy.is_some() {
        "replies on, reading (answering a message now)".to_string()
    } else {
        match age {
            Some(s) if s < READING_SECONDS => format!("replies on, reading (last poll {} ago)", short_ago(s)),
            Some(s) => format!(
                "replies on, NOT reading: last poll {} ago (the watcher is not running, or it only polls once per cycle: cron, the Action)",
                short_ago(s)
            ),
            None => "replies on, NOT reading yet: no poll recorded (start or restart the watcher)".to_string(),
        }
    })
}

/// One incoming text, with what the answer needs to point back at it.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Incoming {
    message_id: i64,
    text: String,
    reply_to: Option<String>,
    /// When the user sent it, as the watcher saw it.
    #[serde(default)]
    received_at: String,
    /// The agent was out when it arrived and this is a later try: the prompt says so.
    #[serde(default)]
    late: bool,
}

/// Messages the agent could not answer (its limit, an error, a timeout), kept in the state dir until it can: a
/// message the user sent is never dropped because the agent was briefly unavailable.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Waiting {
    /// Pacing and reasons, per message id: the same queue the cases use.
    queue: Queue,
    messages: IndexMap<String, Incoming>,
}

const WAITING_FILE: &str = "relay-retries.json";

/// The telegram part of a notifier that reads replies: `(bot token, chat id)`.
fn reader(notifier: &NotifierConfig) -> Option<(&str, &str)> {
    match &notifier.kind {
        NotifierKind::Telegram { bot_token, chat_id, replies: true } => Some((bot_token, chat_id)),
        _ => None,
    }
}

/// Hides the bot token and the config's secrets.
fn scrub(config: &Config, token: &str, text: &str) -> String {
    let hidden = if token.is_empty() { text.to_string() } else { text.replace(token, "[redacted]") };
    redact(config, &hidden)
}

/// Percent-encodes everything but RFC 3986 unreserved characters.
fn url_encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `relay-<first 8 hex of sha256(token)>.json`: the offset of this bot, without the token in a file name.
fn offset_file(token: &str) -> String {
    format!("relay-{}.json", &sha256_hex(token.as_bytes())[..8])
}

/// The answer as sent: trimmed, redacted, at most `REPLY_MAX` characters (`…` at the cut).
fn clip(text: &str) -> String {
    let text = text.trim();
    if text.chars().count() <= REPLY_MAX {
        return text.to_string();
    }
    let head: String = text.chars().take(REPLY_MAX - 1).collect();
    format!("{}…", head.trim_end())
}

/// `<stateDir>/work/relay-<yyyymmddhhmmss>[-n]/`, created fresh (two messages in one second get their own).
fn create_workdir(config: &Config, at: &str) -> Result<PathBuf> {
    let stamp: String = at.chars().filter(char::is_ascii_digit).take(14).collect();
    let parent = config.state_dir.join("work");
    fs::DirBuilder::new().recursive(true).mode(0o700).create(&parent)?;
    for n in 0.. {
        let name = if n == 0 { format!("relay-{stamp}") } else { format!("relay-{stamp}-{}", n + 1) };
        let dir = parent.join(name);
        match fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    unreachable!("the loop only ends by returning")
}

/// The last `URGENT_LINES` urgent lines the watcher sent, oldest first, as the prompt lists them.
fn urgent_lines(config: &Config) -> Vec<String> {
    let entries = unread(&config.state_dir, true).unwrap_or_default();
    let urgent: Vec<_> = entries.iter().filter(|e| e.event == NotifyEvent::Urgent.as_str()).collect();
    urgent[urgent.len().saturating_sub(URGENT_LINES)..].iter().map(|e| format!("- {} {}", e.at, e.title)).collect()
}

/// The prompt: the rules, then what to do, the urgent lines, the message and what it replies to.
fn build_prompt(config: &Config, token: &str, workdir: &Path, at: &str, incoming: &Incoming) -> String {
    let urgent = urgent_lines(config);
    let urgent = if urgent.is_empty() { "none".to_string() } else { urgent.join("\n") };
    let mut prompt = format!(
        "{AGENTS_MD}\n\n## Answering on Telegram\n\nYou are answering the user on Telegram. Do what the message asks under the rules above: merge or close PRs \
         yourself with gh only when clearly asked, after re-checking the PR is open, mergeable and its checks pass. Here the cvecondor command is the local \
         `cvecondor` binary on PATH, not the prefix in deployment.md. Answer in one or two short plain lines in {}/reply.md.\n\n## The last urgent lines \
         they were sent\n{urgent}\n\n## A message from the user (Telegram, {at})\n\n{}\n",
        workdir.display(),
        scrub(config, token, &incoming.text),
    );
    if let Some(replied) = &incoming.reply_to {
        prompt.push_str(&format!("\n## The message they replied to\n\n{}\n", scrub(config, token, replied)));
    }
    if incoming.late {
        prompt.push_str(&format!(
            "\n## Answered late\n\nThe user sent this at {} and the agent could not answer then (its limit or an error). Check that what it asks is still right now before you act on it, and say in the answer that it is late.\n",
            incoming.received_at
        ));
    }
    prompt
}

/// Creates the work dir (`prompt.md`, `AGENTS.md`) and the agent's argv and environment for one message.
fn build_job(config: &Config, token: &str, incoming: &Incoming, at: &str, base: &Env) -> Result<RelayJob> {
    let r = config.responder.as_ref().ok_or_else(|| anyhow!("no responder configured"))?;
    let workdir = create_workdir(config, at)?;
    let prompt = build_prompt(config, token, &workdir, at, incoming);
    let prompt_file = workdir.join("prompt.md");
    let agents_file = workdir.join("AGENTS.md");
    write_file_atomic(&prompt_file, &prompt)?;
    write_file_atomic(&agents_file, AGENTS_MD)?;
    let template = responder_command(config, Mode::Act)?;
    let argv = template
        .iter()
        .map(|arg| {
            arg.replace("{prompt}", &prompt_file.to_string_lossy())
                .replace("{brief}", &agents_file.to_string_lossy())
                .replace("{case}", "")
                .replace("{report}", &workdir.join("reply.md").to_string_lossy())
                .replace("{workdir}", &workdir.to_string_lossy())
                .replace("{mode}", Mode::Act.as_str())
        })
        .collect();
    let mut env = responder_env(
        config,
        base,
        &[
            (format!("{ENV_PREFIX}_WORKDIR"), workdir.to_string_lossy().into_owned()),
            (format!("{ENV_PREFIX}_MODE"), Mode::Act.as_str().to_string()),
            (format!("{ENV_PREFIX}_CONFIG"), config.file.to_string_lossy().into_owned()),
            (format!("{ENV_PREFIX}_STATE_DIR"), config.state_dir.to_string_lossy().into_owned()),
        ],
    );
    // Whatever name it was given, the bot token is not the agent's.
    if !token.is_empty() {
        env.retain(|(_, value)| value != token);
    }
    Ok(RelayJob {
        text: incoming.text.clone(),
        reply_to: incoming.reply_to.clone(),
        stdin: !template.iter().any(|arg| arg.contains("{prompt}")),
        prompt,
        cwd: r.cwd.clone().unwrap_or_else(|| workdir.clone()),
        workdir,
        argv,
        env,
        timeout: AGENT_TIMEOUT,
    })
}

/// Runs the agent in charge for one message and returns its answer: `reply.md`, else stdout, else a note with the exit code.
pub fn run_job(job: &RelayJob) -> Result<String> {
    let _busy = Busy::enter();
    let out = util::run(
        &job.argv,
        &RunOptions {
            stdin: job.stdin.then(|| job.prompt.clone().into_bytes()),
            cwd: Some(job.cwd.clone()),
            env: Some(job.env.clone()),
            timeout: Some(job.timeout),
            max_output: 1 << 20,
            ..RunOptions::default()
        },
    )?;
    if let Ok(reply) = fs::read_to_string(job.workdir.join("reply.md"))
        && !reply.trim().is_empty()
    {
        return Ok(reply);
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    if out.code == Some(0) && !out.timed_out && !stdout.trim().is_empty() {
        return Ok(stdout.into_owned());
    }
    // Not an answer: its limit message, an error, a timeout. The caller queues the message for another try.
    let how = match (out.timed_out, out.code) {
        (true, _) => "timed out".to_string(),
        (false, Some(0)) => "answered nothing".to_string(),
        (false, Some(code)) => format!("exit {code}"),
        (false, None) => "killed by a signal".to_string(),
    };
    let reason = retry::failure_reason(&how, &stdout, &String::from_utf8_lossy(&out.stderr));
    Err(anyhow!("{reason}"))
}

/// An update's message as the relay reads it, `None` when it is not one: `(chat id, text, id, replied-to text)`.
fn read_message(update: &Value) -> Option<(String, Option<Incoming>)> {
    let message = update.get("message")?;
    let chat = message.get("chat")?.get("id")?.as_i64()?.to_string();
    let incoming = match (message.get("message_id").and_then(Value::as_i64), message.get("text").and_then(Value::as_str)) {
        (Some(message_id), Some(text)) if !text.trim().is_empty() => Some(Incoming {
            message_id,
            text: text.to_string(),
            reply_to: message.pointer("/reply_to_message/text").and_then(Value::as_str).filter(|t| !t.trim().is_empty()).map(str::to_string),
            received_at: String::new(),
            late: false,
        }),
        _ => None,
    };
    Some((chat, incoming))
}

/// The same title as a notifier would give a line: one line, at most `TITLE_CHARS` characters.
fn title_of(text: &str) -> String {
    let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    format!("reply: {}", line.chars().take(TITLE_CHARS).collect::<String>())
}

fn send_reply(config: &Config, token: &str, chat_id: &str, to: i64, text: &str, fetch: &dyn Fetch) -> Result<()> {
    let body = json!({ "chat_id": chat_id, "text": text, "reply_to_message_id": to, "allow_sending_without_reply": true, "disable_web_page_preview": true });
    let request = Request::post(format!("{API}/bot{token}/sendMessage"), serde_json::to_vec(&body)?)
        .header("content-type", "application/json")
        .header("user-agent", USER_AGENT)
        .timeout(SEND_TIMEOUT);
    // The response body is never reported: Telegram echoes nothing useful and a proxy may echo the URL.
    let res = fetch.fetch(request).map_err(|e| anyhow!("{}", scrub(config, token, &format!("{e:#}"))))?;
    if !res.ok() {
        bail!("HTTP {}", res.status);
    }
    Ok(())
}

/// One `getUpdates` round and its messages, one at a time in order. Returns how many were handled. Errors never carry
/// the token; a 409 is a `Conflict`.
///
/// `run_agent` answers one message (`run_job` in production); an error from it is told to the user as the answer.
pub fn poll_once(
    config: &Config,
    notifier: &NotifierConfig,
    fetch: &dyn Fetch,
    run_agent: &dyn Fn(&RelayJob) -> Result<String>,
    now: &dyn Fn() -> Timestamp,
    options: &PollOptions,
) -> Result<usize> {
    let Some((token, chat_id)) = reader(notifier) else { bail!("not a telegram notifier with replies") };
    poll(config, token, chat_id, fetch, run_agent, now, options)
        .map_err(|e| if e.downcast_ref::<Conflict>().is_some() { e } else { anyhow!("{}", scrub(config, token, &format!("{e:#}"))) })
        .inspect_err(|e| note_error(config, token, &e.to_string()))
}

fn poll(
    config: &Config,
    token: &str,
    chat_id: &str,
    fetch: &dyn Fetch,
    run_agent: &dyn Fn(&RelayJob) -> Result<String>,
    now: &dyn Fn() -> Timestamp,
    options: &PollOptions,
) -> Result<usize> {
    // Messages the agent could not answer earlier go first, once their time has come.
    let retried = answer_waiting(config, token, chat_id, fetch, run_agent, now, options);
    let file = offset_file(token);
    // No state file at all is the first read of this bot. The file exists from then on, even when nothing was waiting,
    // so the first real message is never taken for the backlog.
    let stored = read_state::<Offset>(&config.state_dir, &file);
    let first = stored.is_none();
    let offset = stored.and_then(|o| o.offset);
    // The first read only catches up with the backlog: it returns at once, so a message sent while it waited is not in it.
    let wait = if first { 0 } else { options.wait_seconds };
    let mut url = format!("{API}/bot{token}/getUpdates?timeout={wait}");
    if let Some(offset) = offset {
        url.push_str(&format!("&offset={offset}"));
    }
    url.push_str(&format!("&allowed_updates={}", url_encode(r#"["message"]"#)));
    let request = Request::get(url).header("user-agent", USER_AGENT).timeout(Duration::from_secs(wait) + POLL_SLACK);
    let res = fetch.fetch(request)?;
    if res.status == 409 {
        return Err(Conflict.into());
    }
    let body: Value = res.json().map_err(|e| anyhow!("getUpdates: HTTP {}: unreadable answer ({e})", res.status))?;
    if !res.ok() || body.get("ok") != Some(&Value::Bool(true)) {
        let why = body.get("description").and_then(Value::as_str).unwrap_or("not ok");
        bail!("getUpdates: HTTP {}: {why}", res.status);
    }
    let updates: &[Value] = body.get("result").and_then(Value::as_array).map_or(&[], Vec::as_slice);
    // Everyone who wrote to the bot is remembered (names only, never texts), also what is skipped or ignored below:
    // `cvecondor telegram-chat` reads this while the relay holds the bot.
    let chats: Vec<Chat> = updates.iter().filter_map(chat_of).collect();
    let t = now();
    note_poll(config, token, t, &chats);
    let last = updates.iter().filter_map(|u| u.get("update_id").and_then(Value::as_i64)).max();

    // From here a message is being taken on: a stopping daemon waits for it, and one that has stopped leaves the batch unread.
    let _busy = Busy::enter();
    if options.stop.is_some_and(|stop| stop.load(Ordering::SeqCst)) {
        return Ok(retried);
    }
    // The first read of a bot starts the conversation now: what was sent before replies were on (perhaps long ago, to
    // an earlier reader) is never acted on.
    if first {
        write_state(&config.state_dir, &file, &Offset { offset: last.map(|l| l + 1) })?;
        options.say(&format!("relay: first read of this bot: skipped {} earlier update(s); replies start now", updates.len()));
        return Ok(retried);
    }
    let Some(last) = last else { return Ok(retried) };
    write_state(&config.state_dir, &file, &Offset { offset: Some(last + 1) })?;
    note_handling(config, token, Some(t));
    let _handling = Handling { config, token };

    let mut waiting: Waiting = read_state(&config.state_dir, WAITING_FILE).unwrap_or_default();
    let mut handled = 0;
    for update in updates {
        let (chat, incoming) = match read_message(update) {
            Some((chat, incoming)) => (chat, incoming),
            None => ("unknown".to_string(), None),
        };
        let mut incoming = match incoming {
            Some(incoming) if chat == chat_id => incoming,
            _ => {
                options.say(&format!("relay: ignored an update from chat {chat}"));
                continue;
            }
        };
        incoming.received_at = iso(now());
        match answer(config, token, chat_id, &incoming, fetch, run_agent, now, options) {
            Ok(()) => handled += 1,
            Err(e) => {
                // The agent could not answer (its limit, an error, a timeout): say so once, keep the message, try again later.
                let reason = scrub(config, token, &format!("{e:#}"));
                let t = now();
                let key = incoming.message_id.to_string();
                waiting.queue.fail(&key, &reason, t, t);
                let next = waiting.queue.entries.get(&key).map(|e| e.next_at.clone()).unwrap_or_default();
                waiting.messages.insert(key, incoming.clone());
                if let Err(e) = write_state(&config.state_dir, WAITING_FILE, &waiting) {
                    options.say(&format!("relay: could not keep the unanswered message: {e:#}"));
                }
                let told = clip(&format!("I can't answer right now ({reason}). I kept your message and will answer it when I can, not before {next}."));
                if let Err(e) = send_reply(config, token, chat_id, incoming.message_id, &told, fetch) {
                    options.say(&format!("relay: could not send the reply: {}", scrub(config, token, &format!("{e:#}"))));
                }
                keep_exchange(config, token, &incoming, &told, now, options);
            }
        }
    }
    Ok(handled + retried)
}

/// Runs the agent on one message and sends its answer back to the chat. An error: the agent did not answer.
#[allow(clippy::too_many_arguments)]
fn answer(
    config: &Config,
    token: &str,
    chat_id: &str,
    incoming: &Incoming,
    fetch: &dyn Fetch,
    run_agent: &dyn Fn(&RelayJob) -> Result<String>,
    now: &dyn Fn() -> Timestamp,
    options: &PollOptions,
) -> Result<()> {
    let at = iso(now());
    let answer = build_job(config, token, incoming, &at, options.env.unwrap_or(&process_env())).and_then(|job| run_agent(&job))?;
    if answer.trim().is_empty() {
        bail!("answered nothing");
    }
    let reply = clip(&scrub(config, token, &answer));
    if let Err(e) = send_reply(config, token, chat_id, incoming.message_id, &reply, fetch) {
        options.say(&format!("relay: could not send the reply: {}", scrub(config, token, &format!("{e:#}"))));
    }
    keep_exchange(config, token, incoming, &reply, now, options);
    Ok(())
}

/// The exchange as the inbox keeps it: what they wrote, what was answered.
fn keep_exchange(config: &Config, token: &str, incoming: &Incoming, reply: &str, now: &dyn Fn() -> Timestamp, options: &PollOptions) {
    let exchange = Notice {
        event: NotifyEvent::Report,
        title: scrub(config, token, &title_of(&incoming.text)),
        text: format!("They wrote:\n{}\n\nThe agent answered:\n{reply}", scrub(config, token, &incoming.text)),
        key: None,
        severity: None,
        urls: None,
        report_path: None,
    };
    if let Err(e) = keep(&config.state_dir, &exchange, now()) {
        options.say(&format!("relay: could not keep the exchange: {e:#}"));
    }
}

/// Answers the kept messages whose time has come, oldest first. The first that fails again stops the round: the agent
/// is still out, and the rest wait with it. Returns how many were answered.
fn answer_waiting(
    config: &Config,
    token: &str,
    chat_id: &str,
    fetch: &dyn Fetch,
    run_agent: &dyn Fn(&RelayJob) -> Result<String>,
    now: &dyn Fn() -> Timestamp,
    options: &PollOptions,
) -> usize {
    let mut waiting: Waiting = read_state(&config.state_dir, WAITING_FILE).unwrap_or_default();
    let due: Vec<String> = waiting.queue.due(now()).iter().map(|e| e.key.clone()).collect();
    let mut answered = 0;
    for key in due {
        if options.stop.is_some_and(|stop| stop.load(Ordering::SeqCst)) {
            break;
        }
        let Some(mut incoming) = waiting.messages.get(&key).cloned() else {
            waiting.queue.replace(&key);
            continue;
        };
        incoming.late = true;
        let _busy = Busy::enter();
        let finished = match answer(config, token, chat_id, &incoming, fetch, run_agent, now, options) {
            Ok(()) => {
                waiting.queue.done(&key);
                waiting.messages.shift_remove(&key);
                answered += 1;
                true
            }
            Err(e) => {
                let t = now();
                waiting.queue.fail(&key, &scrub(config, token, &format!("{e:#}")), t, t);
                false
            }
        };
        if let Err(e) = write_state(&config.state_dir, WAITING_FILE, &waiting) {
            options.say(&format!("relay: could not keep the unanswered messages: {e:#}"));
        }
        if !finished {
            break;
        }
    }
    answered
}

/// Sleeps `duration` in one-second steps, stopping early when `stop` is set.
fn sleep_unless_stopped(stop: &AtomicBool, duration: Duration) {
    let until = Instant::now() + duration;
    while !stop.load(Ordering::SeqCst) && Instant::now() < until {
        thread::sleep(Duration::from_secs(1));
    }
}

/// One polling thread's loop: long poll, answer, repeat, until `stop`.
fn run_loop(config: &Config, notifier: &NotifierConfig, stop: &AtomicBool) {
    let options = PollOptions { stop: Some(stop), ..PollOptions::default() };
    while !stop.load(Ordering::SeqCst) {
        let started = Instant::now();
        match catch_unwind(AssertUnwindSafe(|| poll_once(config, notifier, &Net, &run_job, &util::now, &options))) {
            Ok(Ok(_)) => {
                // A poll that came back at once (a proxy, a fake) must not spin.
                if started.elapsed() < Duration::from_secs(1) {
                    sleep_unless_stopped(stop, Duration::from_secs(1));
                }
            }
            Ok(Err(e)) if e.downcast_ref::<Conflict>().is_some() => {
                util::log(&format!("relay: {e}"));
                sleep_unless_stopped(stop, CONFLICT_BACKOFF);
            }
            Ok(Err(e)) => {
                util::log(&format!("relay: {e}"));
                sleep_unless_stopped(stop, ERROR_BACKOFF);
            }
            Err(_) => {
                util::log("relay: internal error (panic)");
                sleep_unless_stopped(stop, ERROR_BACKOFF);
            }
        }
    }
}

/// Starts one background thread per telegram notifier that reads replies; they end when `stop` is set (a poll in
/// flight is abandoned; one that is answering a message is waited for with `wait_idle`). Returns how many started.
pub fn start(config: &Config, stop: &'static AtomicBool) -> usize {
    let mut started = 0;
    for notifier in config.notify.iter().filter(|n| reader(n).is_some()) {
        let config = config.clone();
        let notifier = notifier.clone();
        match thread::Builder::new().name("relay".to_string()).spawn(move || run_loop(&config, &notifier, stop)) {
            Ok(_) => started += 1,
            Err(e) => util::log(&format!("relay: could not start: {e}")),
        }
    }
    if started > 0 {
        util::log("relay: answering the user's Telegram messages");
    }
    started
}

/// The one-shot `cycle` command's turn: one non-waiting poll per replies notifier, so cron and Action setups answer too.
/// Returns a line for the cycle's output when something was handled.
pub fn poll_cycle(config: &Config) -> Option<String> {
    let mut handled = 0;
    for notifier in config.notify.iter().filter(|n| reader(n).is_some()) {
        // A second one-shot run (or a slow first) never reads the same bot at once.
        let polled = with_lock(&config.state_dir, "relay", || {
            let options = PollOptions { wait_seconds: 0, ..PollOptions::default() };
            poll_once(config, notifier, &Net, &run_job, &util::now, &options)
        });
        match polled {
            Some(Ok(n)) => handled += n,
            Some(Err(e)) => util::log(&format!("relay: {e}")),
            None => util::log("relay: another run is reading replies"),
        }
    }
    (handled > 0).then(|| format!("Replies answered: {handled}"))
}
