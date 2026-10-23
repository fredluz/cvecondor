// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! Delivers a notice (an urgent one-liner, a cycle's cases, a report, secret findings) to every
//! configured notifier: Telegram, Slack, a generic webhook, email over a
//! built-in SMTP client, or a local command. Notifiers run in parallel and fail
//! independently. Tokens, webhook URLs and passwords are secrets: they are
//! scrubbed from every error, and bodies never appear in errors at all.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use indexmap::IndexMap;
use jiff::Timestamp;
use jiff::tz::TimeZone;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::config::{Config, EmailSecurity, NotifierConfig, NotifierKind, NotifyEvent, redact};
use crate::http::{Fetch, Request, TlsStream, tls_config, tls_wrap};
use crate::name::{NAME, USER_AGENT};
use crate::util::{self, RunOptions, base64_encode, iso, parallel_map};

/// A message for the user: an urgent one-liner, a cycle's cases, a report, or secret findings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Notice {
    /// `Urgent` is one short line and is all a notifier gets by default; `Test` reaches every notifier.
    pub event: NotifyEvent,
    /// One line, e.g. `act today: CVE-2026-1234 in acme/api (lodash 4.17.20): working around it now`
    pub title: String,
    /// Plain text body, already redacted by the caller, may be long.
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_path: Option<String>,
}

/// Which notifiers delivered, and the (redacted) error of each that did not.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SendResult {
    pub sent: Vec<String>,
    pub errors: Vec<String>,
}

/// Delivers a notice; what the cycle and the responder are given.
pub type Notifier = Arc<dyn Fn(&Notice) -> SendResult + Send + Sync>;

const HTTP_TIMEOUT: Duration = Duration::from_secs(20);
const SMTP_STEP: Duration = Duration::from_secs(30);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
/// Telegram counts UTF-16 code units, as JS string lengths do; so do the limits below.
const TELEGRAM_PART: usize = 4000;
const TELEGRAM_PARTS: usize = 3;
const SLACK_MAX: usize = 39_000;
/// An urgent notice is one line: what, where, what is being done. Longer is cut, and the body is dropped.
const URGENT_MAX: usize = 300;

/// Delivers `notice` to every notifier that lists its event (`test` reaches all of them), in
/// parallel. An urgent notice is cut to one line and loses its body first. A failing notifier
/// does not stop the others; its error (scrubbed of its own secrets, then of the config's) lands in `errors`.
pub fn send_notice(config: &Config, notice: &Notice, fetch: &dyn Fetch, now: Timestamp) -> SendResult {
    let targets: Vec<&NotifierConfig> = config.notify.iter().filter(|n| notice.event == NotifyEvent::Test || n.events.contains(&notice.event)).collect();
    let urgent;
    let notice = if notice.event == NotifyEvent::Urgent {
        urgent = Notice { title: urgent_line(&notice.title), text: String::new(), ..notice.clone() };
        &urgent
    } else {
        notice
    };
    let results = parallel_map(&targets, targets.len(), |n| {
        let label = label_of(n);
        match deliver(n, notice, fetch, now) {
            Ok(()) => (label, None),
            Err(err) => {
                // Config secrets may be literals that redact() doesn't know, so scrub this notifier's own first.
                let error = redact(config, &format!("{label}: {}", scrub(n, &format!("{err:#}"))));
                (label, Some(error))
            }
        }
    });
    let mut out = SendResult::default();
    for (label, error) in results {
        match error {
            None => out.sent.push(label),
            Some(error) => out.errors.push(error),
        }
    }
    out
}

fn label_of(n: &NotifierConfig) -> String {
    match &n.kind {
        NotifierKind::Email { to, .. } => format!("email:{}", to.join(",")),
        NotifierKind::Command { command } => {
            let program = command.first().map_or("", String::as_str);
            format!("command:{}", Path::new(program).file_name().map_or("", |s| s.to_str().unwrap_or("")))
        }
        _ => n.type_name().to_string(),
    }
}

fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// An urgent title as one line of at most 300 UTF-16 units: whitespace runs collapse to one space
/// (JS `\s`: Unicode white space, plus U+FEFF, minus U+0085), longer is cut to 299 and `…`.
/// A cut that would land inside a surrogate pair backs off before it.
fn urgent_line(title: &str) -> String {
    let is_space = |c: char| (c.is_whitespace() && c != '\u{85}') || c == '\u{feff}';
    let line = title.split(is_space).filter(|w| !w.is_empty()).collect::<Vec<_>>().join(" ");
    if utf16_len(&line) <= URGENT_MAX {
        return line;
    }
    let mut out = String::new();
    let mut units = 0;
    for c in line.chars() {
        units += c.len_utf16();
        if units > URGENT_MAX - 1 {
            break;
        }
        out.push(c);
    }
    out.push('…');
    out
}

fn scrub(n: &NotifierConfig, message: &str) -> String {
    let mut hide: Vec<&str> = match &n.kind {
        NotifierKind::Telegram { bot_token, .. } => vec![bot_token],
        NotifierKind::Slack { webhook_url } => vec![webhook_url],
        NotifierKind::Webhook { url, headers } => std::iter::once(url.as_str()).chain(headers.values().map(String::as_str)).collect(),
        NotifierKind::Email { pass, .. } => vec![pass.as_deref().unwrap_or("")],
        NotifierKind::Command { .. } => vec![],
    };
    hide.retain(|s| utf16_len(s) >= 4);
    hide.sort_by_key(|s| std::cmp::Reverse(utf16_len(s)));
    let mut out = message.to_string();
    for s in hide {
        out = out.replace(s, "[redacted]");
    }
    out
}

fn deliver(n: &NotifierConfig, notice: &Notice, fetch: &dyn Fetch, now: Timestamp) -> Result<()> {
    match &n.kind {
        NotifierKind::Telegram { bot_token, chat_id, .. } => telegram(bot_token, chat_id, notice, fetch),
        NotifierKind::Slack { webhook_url } => {
            let text = format!("*{}*\n{}", notice.title, notice.text);
            let text = if utf16_len(&text) <= SLACK_MAX {
                text
            } else {
                let units: Vec<u16> = text.encode_utf16().take(SLACK_MAX - 1).collect();
                format!("{}…", utf16_to_string(&units))
            };
            post(fetch, webhook_url, &json!({ "text": text }), &IndexMap::new())
        }
        NotifierKind::Webhook { url, headers } => {
            let mut body = Map::new();
            body.insert("tool".into(), json!(NAME));
            body.insert("event".into(), json!(notice.event.as_str()));
            body.insert("title".into(), json!(notice.title));
            body.insert("text".into(), json!(notice.text));
            // Absent fields are left out, as JSON.stringify leaves out undefined.
            if let Some(key) = &notice.key {
                body.insert("key".into(), json!(key));
            }
            if let Some(severity) = &notice.severity {
                body.insert("severity".into(), json!(severity));
            }
            if let Some(urls) = &notice.urls {
                body.insert("urls".into(), json!(urls));
            }
            if let Some(report) = &notice.report_path {
                body.insert("report".into(), json!(report));
            }
            body.insert("at".into(), json!(iso(now)));
            post(fetch, url, &Value::Object(body), headers)
        }
        NotifierKind::Email { host, port, security, user, pass, from, to } => {
            let target = EmailTarget { host, port: *port, security: *security, user: user.as_deref(), pass: pass.as_deref(), from, to };
            email(&target, notice, now)
        }
        NotifierKind::Command { command } => run_command(command, notice),
    }
}

fn post(fetch: &dyn Fetch, url: &str, body: &Value, headers: &IndexMap<String, String>) -> Result<()> {
    let mut req =
        Request::post(url, serde_json::to_vec(body)?).header("content-type", "application/json").header("user-agent", USER_AGENT).timeout(HTTP_TIMEOUT);
    // The notifier's own headers win over the defaults.
    for (key, value) in headers {
        req.headers.retain(|(name, _)| !name.eq_ignore_ascii_case(key));
        req = req.header(key.as_str(), value.as_str());
    }
    // The response body is never reported: it can echo the URL.
    let res = fetch.fetch(req)?;
    if !res.ok() {
        bail!("HTTP {}", res.status);
    }
    Ok(())
}

fn telegram(bot_token: &str, chat_id: &str, notice: &Notice, fetch: &dyn Fetch) -> Result<()> {
    let url = format!("https://api.telegram.org/bot{bot_token}/sendMessage");
    let full = if notice.text.is_empty() { notice.title.clone() } else { format!("{}\n\n{}", notice.title, notice.text) };
    for text in telegram_parts(&full, notice.report_path.as_deref()) {
        post(fetch, &url, &json!({ "chat_id": chat_id, "text": text, "disable_web_page_preview": true }), &IndexMap::new())?;
    }
    Ok(())
}

/// A JS string slice never splits a character here (`cut` backs off a surrogate pair), so this is lossless.
fn utf16_to_string(units: &[u16]) -> String {
    String::from_utf16_lossy(units)
}

/// Splits at line breaks where possible; past three parts the rest points at the report file.
fn telegram_parts(full: &str, report_path: Option<&str>) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut rest: Vec<u16> = full.encode_utf16().collect();
    while rest.len() > TELEGRAM_PART {
        if parts.len() == TELEGRAM_PARTS - 1 {
            let note = format!("\n… truncated{}", report_path.map(|p| format!(", full report: {p}")).unwrap_or_default());
            let (head, _) = cut(&rest, TELEGRAM_PART.saturating_sub(utf16_len(&note)));
            parts.push(format!("{}{note}", utf16_to_string(head)));
            return parts;
        }
        let (head, tail) = cut(&rest, TELEGRAM_PART);
        parts.push(utf16_to_string(head));
        rest = tail.to_vec();
    }
    parts.push(utf16_to_string(&rest));
    parts
}

/// Cuts `text` (UTF-16 units) at the last line break at or before `max`, or at `max` when that
/// break is in the first half; the break itself is dropped from the tail.
fn cut(text: &[u16], max: usize) -> (&[u16], &[u16]) {
    let newline = u16::from(b'\n');
    let last = text.iter().take(max + 1).rposition(|&u| u == newline);
    let mut at = match last {
        Some(i) if i * 2 >= max => i,
        _ => max,
    };
    at = at.min(text.len());
    // Never split a surrogate pair.
    if at > 0 && (0xd800..=0xdbff).contains(&text[at - 1]) {
        at -= 1;
    }
    let tail = &text[at..];
    (&text[..at], tail.strip_prefix(&[newline]).unwrap_or(tail))
}

/// What a command (and an email) is sent: the text, else the title.
fn command_input(notice: &Notice) -> &str {
    if notice.text.is_empty() { &notice.title } else { &notice.text }
}

fn run_command(argv: &[String], notice: &Notice) -> Result<()> {
    // `vars_os`: a variable that isn't valid Unicode is passed through lossily instead of panicking the cycle.
    let mut env: Vec<(String, String)> =
        std::env::vars_os().map(|(k, v)| (k.to_string_lossy().into_owned(), v.to_string_lossy().into_owned())).collect();
    env.extend([
        ("NOTICE_EVENT".to_string(), notice.event.as_str().to_string()),
        ("NOTICE_TITLE".to_string(), notice.title.clone()),
        ("NOTICE_KEY".to_string(), notice.key.clone().unwrap_or_default()),
        ("NOTICE_REPORT".to_string(), notice.report_path.clone().unwrap_or_default()),
    ]);
    // Output is ignored (max_output 0 reads and drops it); a command that ignores stdin closes the pipe early and its exit code decides.
    let opts = RunOptions {
        stdin: Some(command_input(notice).as_bytes().to_vec()),
        env: Some(env),
        timeout: Some(COMMAND_TIMEOUT),
        max_output: 0,
        ..RunOptions::default()
    };
    let out = match util::run(argv, &opts) {
        Ok(out) => out,
        Err(err) => {
            let code = err.downcast_ref::<util::SpawnError>().map_or("error", |e| errno_name(&e.source));
            bail!("could not run ({code})");
        }
    };
    if out.timed_out {
        bail!("killed by SIGKILL");
    }
    match out.code {
        Some(0) => Ok(()),
        Some(code) => bail!("exit {code}"),
        None => bail!("killed by signal"),
    }
}

// --- SMTP --------------------------------------------------------------------

struct Reply {
    code: u32,
    text: String,
}

enum Conn {
    Plain(TcpStream),
    Tls(Box<TlsStream>),
    /// Between the plain stream and its TLS replacement.
    Closed,
}

impl Conn {
    fn tcp(&self) -> Option<&TcpStream> {
        match self {
            Self::Plain(s) => Some(s),
            Self::Tls(s) => Some(s.get_ref()),
            Self::Closed => None,
        }
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            Self::Tls(s) => s.read(buf),
            Self::Closed => Err(io::ErrorKind::NotConnected.into()),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(buf),
            Self::Tls(s) => s.write(buf),
            Self::Closed => Err(io::ErrorKind::NotConnected.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls(s) => s.flush(),
            Self::Closed => Ok(()),
        }
    }
}

/// The node-style name of an I/O failure (`ECONNREFUSED`, …); the error kind's words when there is none.
fn errno_name(err: &io::Error) -> &'static str {
    match err.raw_os_error() {
        Some(libc::ECONNREFUSED) => "ECONNREFUSED",
        Some(libc::ECONNRESET) => "ECONNRESET",
        Some(libc::ETIMEDOUT) => "ETIMEDOUT",
        Some(libc::ENETUNREACH) => "ENETUNREACH",
        Some(libc::EHOSTUNREACH) => "EHOSTUNREACH",
        Some(libc::EPIPE) => "EPIPE",
        Some(libc::ENOENT) => "ENOENT",
        Some(libc::EACCES) => "EACCES",
        _ => match err.kind() {
            io::ErrorKind::NotFound => "ENOENT",
            io::ErrorKind::PermissionDenied => "EACCES",
            io::ErrorKind::ConnectionRefused => "ECONNREFUSED",
            io::ErrorKind::ConnectionReset => "ECONNRESET",
            io::ErrorKind::BrokenPipe => "EPIPE",
            _ => "error",
        },
    }
}

fn is_timeout(err: &io::Error) -> bool {
    matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

/// One SMTP connection: replies are read in whole (multi-line `250-…` continuations joined up to the `250 ` line), each bounded to 30 s.
struct Smtp {
    conn: Conn,
    buf: Vec<u8>,
}

impl Smtp {
    fn connect(host: &str, port: u16, tls: bool) -> Result<Self> {
        let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs().map_err(|_| anyhow!("connect failed (ENOTFOUND)"))?.collect();
        let mut failure = anyhow!("connect failed (ENOTFOUND)");
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, SMTP_STEP) {
                Ok(tcp) => {
                    tcp.set_write_timeout(Some(SMTP_STEP))?;
                    tcp.set_read_timeout(Some(SMTP_STEP))?;
                    let conn = if tls { Conn::Tls(Box::new(upgrade(tcp, host)?)) } else { Conn::Plain(tcp) };
                    return Ok(Self { conn, buf: Vec::new() });
                }
                Err(err) if is_timeout(&err) => failure = anyhow!("SMTP timeout"),
                Err(err) => failure = anyhow!("connect failed ({})", errno_name(&err)),
            }
        }
        Err(failure)
    }

    /// STARTTLS: the handshake runs on the same socket. Anything buffered in clear is dropped.
    fn start_tls(&mut self, host: &str) -> Result<()> {
        let Conn::Plain(tcp) = std::mem::replace(&mut self.conn, Conn::Closed) else { bail!("connection already secure") };
        self.buf.clear();
        self.conn = Conn::Tls(Box::new(upgrade(tcp, host)?));
        Ok(())
    }

    fn write_raw(&mut self, data: &[u8]) -> Result<()> {
        self.conn
            .write_all(data)
            .and_then(|()| self.conn.flush())
            .map_err(|err| if is_timeout(&err) { anyhow!("SMTP timeout") } else { anyhow!("connection error ({})", errno_name(&err)) })
    }

    fn send(&mut self, line: &str) -> Result<()> {
        self.write_raw(format!("{line}\r\n").as_bytes())
    }

    fn read_reply(&mut self) -> Result<Reply> {
        let deadline = Instant::now() + SMTP_STEP;
        let mut lines: Vec<String> = Vec::new();
        loop {
            while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                let raw: Vec<u8> = self.buf.drain(..=pos).collect();
                let mut line = String::from_utf8_lossy(&raw[..pos]).into_owned();
                if line.ends_with('\r') {
                    line.pop();
                }
                lines.push(line.chars().skip(4).collect());
                let bytes = line.as_bytes();
                let continued = bytes.len() >= 4 && bytes[..3].iter().all(u8::is_ascii_digit) && bytes[3] == b'-';
                if !continued {
                    let code = line.chars().take(3).collect::<String>().trim().parse().unwrap_or(0);
                    return Ok(Reply { code, text: lines.join("\n") });
                }
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) else { bail!("SMTP timeout") };
            if let Some(tcp) = self.conn.tcp() {
                tcp.set_read_timeout(Some(remaining))?;
            }
            let mut chunk = [0u8; 4096];
            match self.conn.read(&mut chunk) {
                Ok(0) => bail!("connection closed"),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => bail!("connection closed"),
                Err(err) if is_timeout(&err) => bail!("SMTP timeout"),
                Err(err) => bail!("connection error ({})", errno_name(&err)),
            }
        }
    }

    /// Reads a reply and requires `ok`. `hide_text`: the server's words stay out of the error (authentication).
    fn expect(&mut self, what: &str, ok: u32, hide_text: bool) -> Result<Reply> {
        let reply = self.read_reply()?;
        if reply.code != ok {
            let first: String = reply.text.split('\n').next().unwrap_or("").chars().take(200).collect();
            bail!("SMTP {what}: {}{}", reply.code, if hide_text { String::new() } else { format!(" {first}") });
        }
        Ok(reply)
    }
}

fn upgrade(tcp: TcpStream, host: &str) -> Result<TlsStream> {
    let config = tls_config(None, None).map_err(|e| anyhow!("connect failed ({e:#})"))?;
    tls_wrap(tcp, host, config).map_err(|err| {
        let timed_out = err.chain().filter_map(|e| e.downcast_ref::<io::Error>()).any(is_timeout);
        if timed_out { anyhow!("SMTP timeout") } else { anyhow!("connect failed ({err:#})") }
    })
}

struct EmailTarget<'a> {
    host: &'a str,
    port: u16,
    security: EmailSecurity,
    user: Option<&'a str>,
    pass: Option<&'a str>,
    from: &'a str,
    to: &'a [String],
}

/// This machine's name for EHLO, restricted to what every server accepts.
fn helo_name() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: buf is valid for buf.len() bytes; gethostname writes at most that many.
    let ok = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0;
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let name: String =
        if ok { String::from_utf8_lossy(&buf[..len]).chars().filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-').collect() } else { String::new() };
    if name.is_empty() { "localhost".to_string() } else { name }
}

/// `STARTTLS` at the start of a line of the EHLO text (case-insensitive, whole word).
fn offers_starttls(ehlo: &str) -> bool {
    ehlo.lines().any(|line| {
        let b = line.as_bytes();
        b.len() >= 8 && b[..8].eq_ignore_ascii_case(b"STARTTLS") && b.get(8).is_none_or(|c| !(c.is_ascii_alphanumeric() || *c == b'_'))
    })
}

/// The mechanisms of the first `AUTH <list>` / `AUTH=<list>` line, upper-cased.
fn auth_mechanisms(ehlo: &str) -> Vec<String> {
    for line in ehlo.lines() {
        let b = line.as_bytes();
        if b.len() >= 5 && b[..4].eq_ignore_ascii_case(b"AUTH") && (b[4] == b' ' || b[4] == b'=') {
            return line[5..].to_uppercase().split_whitespace().map(str::to_string).collect();
        }
    }
    Vec::new()
}

/// `Name <a@b>` in config; the envelope wants just `a@b`.
fn envelope_address(address: &str) -> &str {
    if let Some(open) = address.find('<')
        && let Some(close) = address[open..].find('>')
    {
        return &address[open + 1..open + close];
    }
    address.trim()
}

fn email(n: &EmailTarget, notice: &Notice, now: Timestamp) -> Result<()> {
    let mut smtp = Smtp::connect(n.host, n.port, n.security == EmailSecurity::Tls)?;
    let helo = helo_name();

    smtp.expect("greeting", 220, false)?;
    smtp.send(&format!("EHLO {helo}"))?;
    let mut ehlo = smtp.expect("EHLO", 250, false)?;
    if n.security == EmailSecurity::Starttls {
        if !offers_starttls(&ehlo.text) {
            bail!("SMTP server does not offer STARTTLS");
        }
        smtp.send("STARTTLS")?;
        smtp.expect("STARTTLS", 220, false)?;
        smtp.start_tls(n.host)?;
        smtp.send(&format!("EHLO {helo}"))?;
        ehlo = smtp.expect("EHLO", 250, false)?;
    }
    if let (Some(user), Some(pass)) = (n.user, n.pass) {
        let mechs = auth_mechanisms(&ehlo.text);
        let b64 = |s: &str| base64_encode(s.as_bytes());
        let mut plain = mechs.iter().any(|m| m == "PLAIN") || !mechs.iter().any(|m| m == "LOGIN");
        if plain {
            smtp.send(&format!("AUTH PLAIN {}", b64(&format!("\0{user}\0{pass}"))))?;
            let reply = smtp.read_reply()?;
            if reply.code == 504 && mechs.iter().any(|m| m == "LOGIN") {
                plain = false;
            } else if reply.code != 235 {
                bail!("SMTP AUTH: {}", reply.code);
            }
        }
        if !plain {
            smtp.send("AUTH LOGIN")?;
            smtp.expect("AUTH", 334, true)?;
            smtp.send(&b64(user))?;
            smtp.expect("AUTH", 334, true)?;
            smtp.send(&b64(pass))?;
            smtp.expect("AUTH", 235, true)?;
        }
    }
    let envelope = std::iter::once(("MAIL FROM", n.from)).chain(n.to.iter().map(|to| ("RCPT TO", to.as_str())));
    for (verb, address) in envelope {
        smtp.send(&format!("{verb}:<{}>", envelope_address(address)))?;
        let reply = smtp.read_reply()?;
        if reply.code != 250 && !(verb == "RCPT TO" && reply.code == 251) {
            bail!("SMTP {verb}: {}", reply.code);
        }
    }
    smtp.send("DATA")?;
    smtp.expect("DATA", 354, false)?;
    smtp.write_raw(format!("{}\r\n.\r\n", dot_stuff(&message(n, notice, now))).as_bytes())?;
    smtp.expect("message", 250, false)?;
    // The server's goodbye (or its absence) does not matter: the message is queued.
    let _ = smtp.send("QUIT");
    let _ = smtp.read_reply();
    Ok(())
}

/// A line that starts with `.` gets a second one, so the message cannot end the DATA early.
fn dot_stuff(message: &str) -> String {
    let stuffed = message.replace("\r\n.", "\r\n..");
    if stuffed.starts_with('.') { format!(".{stuffed}") } else { stuffed }
}

/// A fresh random UUID (v4) for the Message-ID: 16 bytes of /dev/urandom, no crate.
fn random_uuid() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut b = [0u8; 16];
    if File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).is_err() {
        // No entropy device: a hash of the clock, the pid and a counter is still unique per message.
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        let hex = util::sha256_hex(format!("{nanos}-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst)).as_bytes());
        for (i, byte) in b.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0);
        }
    }
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: Vec<String> = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", h[0..4].concat(), h[4..6].concat(), h[6..8].concat(), h[8..10].concat(), h[10..16].concat())
}

fn one_line(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_break = false;
    for c in s.chars() {
        if c == '\r' || c == '\n' {
            if !in_break {
                out.push(' ');
            }
            in_break = true;
        } else {
            in_break = false;
            out.push(c);
        }
    }
    out
}

fn message(n: &EmailTarget, notice: &Notice, now: Timestamp) -> String {
    let encoded = base64_encode(command_input(notice).as_bytes());
    // Base64 is ASCII: 76 characters per line, no break after the last.
    let body = encoded.as_bytes().chunks(76).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join("\r\n");
    let date = now.to_zoned(TimeZone::UTC).strftime("%a, %d %b %Y %H:%M:%S +0000");
    [
        format!("From: {}", one_line(n.from)),
        format!("To: {}", n.to.iter().map(|t| one_line(t)).collect::<Vec<_>>().join(", ")),
        format!("Subject: {}", encode_header(&one_line(&notice.title))),
        format!("Date: {date}"),
        format!("Message-ID: <{}@{NAME}>", random_uuid()),
        "MIME-Version: 1.0".to_string(),
        "Content-Type: text/plain; charset=utf-8".to_string(),
        "Content-Transfer-Encoding: base64".to_string(),
        String::new(),
        body,
    ]
    .join("\r\n")
}

/// RFC 2047 encoded-words, each ≤ 75 chars and never splitting a character.
fn encode_header(value: &str) -> String {
    if value.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return value.to_string();
    }
    let mut words: Vec<&str> = Vec::new();
    let mut start = 0;
    for (i, ch) in value.char_indices() {
        if i + ch.len_utf8() - start > 45 {
            words.push(&value[start..i]);
            start = i;
        }
    }
    if start < value.len() {
        words.push(&value[start..]);
    }
    words.iter().map(|w| format!("=?UTF-8?B?{}?=", base64_encode(w.as_bytes()))).collect::<Vec<_>>().join("\r\n ")
}
