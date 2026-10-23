// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! Small shared helpers: time (JS `Date` equivalents), base64, SHA-256, logging,
//! bounded parallel map and child processes with a timeout and capped output.

use std::fmt;
use std::io::{Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use jiff::Timestamp;
use jiff::civil::{Date, DateTime};
use jiff::tz::{Offset, TimeZone};
use regex::Regex;
use sha2::{Digest, Sha256};

// ---------- JS strings ----------

/// The JS `\s` class as a regex bracket class: `[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]`.
/// Rust's `\s` (White_Space) has U+0085 and lacks the BOM U+FEFF, JS's the reverse. Usable inside another class (nested union).
pub const JS_WS: &str = r"[\t\n\x0B\x0C\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}]";

/// The JS `\S` class: everything but `JS_WS`.
pub const JS_NOT_WS: &str = r"[^\t\n\x0B\x0C\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}]";

/// Compiles `pattern` with every `\s` read as the JS class (`JS_WS`) and every `\S` as `JS_NOT_WS`.
/// Panics on an invalid pattern: call it with literals only.
pub fn js_regex(pattern: &str) -> Regex {
    let mut out = String::with_capacity(pattern.len() + 64);
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('s') => out.push_str(JS_WS),
            Some('S') => out.push_str(JS_NOT_WS),
            Some(escaped) => {
                out.push('\\');
                out.push(escaped);
            }
            None => out.push('\\'),
        }
    }
    Regex::new(&out).expect("valid regex")
}

/// A character JS `\s` and `String.prototype.trim` treat as white space: Unicode White_Space plus the BOM, minus U+0085.
pub fn is_js_space(c: char) -> bool {
    (c.is_whitespace() && c != '\u{85}') || c == '\u{feff}'
}

/// JS `String.prototype.trim`.
pub fn js_trim(text: &str) -> &str {
    text.trim_matches(is_js_space)
}

/// JS `String.prototype.trimStart`.
pub fn js_trim_start(text: &str) -> &str {
    text.trim_start_matches(is_js_space)
}

// ---------- time ----------

pub fn now() -> Timestamp {
    Timestamp::now()
}

/// JS `toISOString()`: `2026-10-21T06:00:00.000Z`, always milliseconds and `Z`.
pub fn iso(ts: Timestamp) -> String {
    ts.to_zoned(TimeZone::UTC).strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

static ISO_TIME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^([+-][0-9]{6}|[0-9]{4})(?:-([0-9]{2})(?:-([0-9]{2}))?)?(?:[Tt ]([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:[.,]([0-9]+))?)?)?\s*((?i:Z|UTC|GMT)|[+-][0-9]{2}(?::?[0-9]{2})?)?$",
    )
    .expect("valid regex")
});

/// The optional time of day, zone name or numeric offset and trailing comment both month-name forms end with.
const NAMED_TAIL: &str = r"(?:\s+(?P<h>[0-9]{1,2}):(?P<mi>[0-9]{2})(?::(?P<s>[0-9]{2}))?)?\s*(?:(?P<zone>GMT|UTC?|Z|[ECMP][SD]T)|(?:GMT|UTC?)?(?P<num>[+-][0-9]{2}:?[0-9]{2}))?\s*(?:\(.*\))?$";

/// An optional weekday name, then `21 Oct 2026` (RFC 2822 and what it loosely allows: no space after the comma, no time).
static RFC2822_TIME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r"(?i)^(?:[a-z]{{3,9}}(?:,\s*|\s+))?(?P<d>[0-9]{{1,2}})[\s-]+(?P<mon>[a-z]{{3,9}})\.?,?[\s-]+(?P<y>[0-9]{{4}}|[0-9]{{2}}){NAMED_TAIL}"))
        .expect("valid regex")
});

/// An optional weekday name, then `Oct 21, 2026` / `October 21 2026` (comma optional).
static MONTH_FIRST_TIME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r"(?i)^(?:[a-z]{{3,9}}(?:,\s*|\s+))?(?P<mon>[a-z]{{3,9}})\.?\s+(?P<d>[0-9]{{1,2}}),?\s+(?P<y>[0-9]{{4}}){NAMED_TAIL}")).expect("valid regex")
});

const MONTHS: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];

/// JS `Date.parse` for what feeds and APIs send: ISO 8601 (`2026-10-21`, with or
/// without time, milliseconds and offset) and RFC 2822 (`Wed, 21 Oct 2026 06:00:00 GMT`).
/// Date-only is UTC midnight. JS reads a date-time without an offset as local time;
/// here it is UTC, so results do not depend on the machine's zone.
pub fn parse_time(s: &str) -> Option<Timestamp> {
    let s = js_trim(s);
    parse_iso(s).or_else(|| parse_rfc2822(s))
}

fn parse_iso(s: &str) -> Option<Timestamp> {
    let c = ISO_TIME.captures(s)?;
    let num = |i: usize| c.get(i).map(|m| m.as_str().parse::<i32>().ok()).unwrap_or(Some(0));
    let year: i32 = c[1].parse().ok()?;
    let month = if c.get(2).is_some() { num(2)? } else { 1 };
    let day = if c.get(3).is_some() { num(3)? } else { 1 };
    let (hour, minute, second) = (num(4)?, num(5)?, num(6)?);
    // Milliseconds, like a JS Date: extra digits are cut, not rounded.
    let millis: i32 = match c.get(7) {
        Some(m) => format!("{:0<3}", &m.as_str()[..m.as_str().len().min(3)]).parse().ok()?,
        None => 0,
    };
    let offset = match c.get(8).map(|m| m.as_str()) {
        None => 0,
        Some(z) if z.eq_ignore_ascii_case("z") || z.eq_ignore_ascii_case("utc") || z.eq_ignore_ascii_case("gmt") => 0,
        Some(o) => {
            let sign = if o.starts_with('-') { -1 } else { 1 };
            let digits: String = o[1..].chars().filter(char::is_ascii_digit).collect();
            let hh: i32 = digits.get(..2)?.parse().ok()?;
            let mm: i32 = digits.get(2..).filter(|m| !m.is_empty()).map_or(Some(0), |m| m.parse().ok())?;
            if hh > 23 || mm > 59 {
                return None;
            }
            sign * (hh * 3600 + mm * 60)
        }
    };
    build_time(year, month, day, hour, minute, second, millis, offset)
}

#[allow(clippy::too_many_arguments)]
fn build_time(year: i32, month: i32, day: i32, hour: i32, minute: i32, second: i32, millis: i32, offset: i32) -> Option<Timestamp> {
    if !(1..=12).contains(&month) || minute > 59 || second > 59 || hour > 24 {
        return None;
    }
    // `24:00:00.000` is the end of the day; anything later in hour 24 is invalid.
    if hour == 24 && (minute, second, millis) != (0, 0, 0) {
        return None;
    }
    let date = Date::new(i16::try_from(year).ok()?, month as i8, 1).ok()?;
    if day < 1 || day > i32::from(date.days_in_month()) {
        return None;
    }
    let mut dt = DateTime::new(date.year(), month as i8, day as i8, hour.min(23) as i8, minute as i8, second as i8, millis * 1_000_000).ok()?;
    if hour == 24 {
        dt = dt.checked_add(jiff::Span::new().hours(1)).ok()?;
    }
    Offset::from_seconds(offset).ok()?.to_timestamp(dt).ok()
}

fn parse_rfc2822(s: &str) -> Option<Timestamp> {
    let c = RFC2822_TIME.captures(s).or_else(|| MONTH_FIRST_TIME.captures(s))?;
    let day: i32 = c["d"].parse().ok()?;
    let month = MONTHS.iter().position(|m| c["mon"].to_ascii_lowercase().starts_with(m))? as i32 + 1;
    let mut year: i32 = c["y"].parse().ok()?;
    if c["y"].len() == 2 {
        year += if year < 50 { 2000 } else { 1900 };
    }
    // The time is optional (`Wed, 21 Oct 2026`, `Oct 21, 2026`): midnight.
    let num = |name: &str| c.name(name).map_or(Some(0), |m| m.as_str().parse().ok());
    let (hour, minute, second) = (num("h")?, num("mi")?, num("s")?);
    let offset = if let Some(zone) = c.name("zone") {
        match zone.as_str().to_ascii_uppercase().as_str() {
            "EST" | "CDT" => -5 * 3600,
            "EDT" => -4 * 3600,
            "CST" | "MDT" => -6 * 3600,
            "MST" | "PDT" => -7 * 3600,
            "PST" => -8 * 3600,
            _ => 0,
        }
    } else if let Some(numeric) = c.name("num") {
        let o = numeric.as_str();
        let sign = if o.starts_with('-') { -1 } else { 1 };
        let digits: String = o[1..].chars().filter(char::is_ascii_digit).collect();
        let (hh, mm): (i32, i32) = (digits[..2].parse().ok()?, digits[2..].parse().ok()?);
        if hh > 23 || mm > 59 {
            return None;
        }
        sign * (hh * 3600 + mm * 60)
    } else {
        0
    };
    build_time(year, month, day, hour, minute, second, 0, offset)
}

/// `YYYY-MM-DD` of `ts` in the IANA zone `tz`, or in a fixed UTC offset (`+01:00`, `-0200`: what `Intl.DateTimeFormat`
/// accepts too); UTC when the zone is unknown (watch.ts `localDate`).
pub fn local_date(ts: Timestamp, tz: &str) -> String {
    static OFFSET_ZONE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([+-])([0-9]{2}):?([0-9]{2})$").expect("valid regex"));
    let fixed = OFFSET_ZONE.captures(tz).and_then(|c| {
        let (hh, mm): (i32, i32) = (c[2].parse().ok()?, c[3].parse().ok()?);
        if hh > 23 || mm > 59 {
            return None;
        }
        let seconds = (hh * 3600 + mm * 60) * if &c[1] == "-" { -1 } else { 1 };
        Some(TimeZone::fixed(Offset::from_seconds(seconds).ok()?))
    });
    let zone = fixed.or_else(|| TimeZone::get(tz).ok()).unwrap_or(TimeZone::UTC);
    ts.to_zoned(zone).strftime("%Y-%m-%d").to_string()
}

// ---------- hashing and encoding ----------

pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard alphabet, padded.
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16) | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8) | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Standard alphabet; whitespace is ignored and trailing padding is optional.
pub fn base64_decode(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    let mut padding = false;
    for c in s.bytes().filter(|b| !b.is_ascii_whitespace()) {
        if c == b'=' {
            padding = true;
            continue;
        }
        if padding {
            bail!("invalid base64: data after padding");
        }
        let v = B64.iter().position(|&x| x == c).ok_or_else(|| anyhow!("invalid base64 character {:?}", c as char))? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

// ---------- logging ----------

/// One log line on stderr, prefixed with the time.
pub fn log(line: &str) {
    eprintln!("{} {line}", iso(now()));
}

// ---------- parallel map ----------

/// `items.map(f)` on at most `threads` scoped threads; results keep the order of `items`.
pub fn parallel_map<T: Sync, R: Send>(items: &[T], threads: usize, f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let n = items.len();
    let workers = threads.clamp(1, n.max(1));
    if workers == 1 {
        return items.iter().map(f).collect();
    }
    let next = AtomicUsize::new(0);
    let slots: Vec<Mutex<Option<R>>> = (0..n).map(|_| Mutex::new(None)).collect();
    thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    if i >= n {
                        break;
                    }
                    let result = f(&items[i]);
                    *slots[i].lock().unwrap_or_else(PoisonError::into_inner) = Some(result);
                }
            });
        }
    });
    slots.into_iter().map(|slot| slot.into_inner().unwrap_or_else(PoisonError::into_inner).expect("every slot is filled")).collect()
}

// ---------- processes ----------

pub struct RunOptions {
    pub stdin: Option<Vec<u8>>,
    pub cwd: Option<PathBuf>,
    /// `Some`: the child's environment is cleared, then exactly these are set. `None`: inherited.
    pub env: Option<Vec<(String, String)>>,
    /// SIGTERM to the child's process group when it runs out (SIGKILL ten seconds later if anything in the group ignores it).
    pub timeout: Option<Duration>,
    /// Per stream: output beyond it is read and dropped (`RunOutput::truncated`), and the child's group gets SIGTERM
    /// (then SIGKILL after ten seconds) as soon as the cap is passed.
    pub max_output: usize,
    /// stdout and stderr go to /dev/null: nothing is read, and a process left running by the child cannot hold the call open.
    pub discard_output: bool,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self { stdin: None, cwd: None, env: None, timeout: None, max_output: 64 << 20, discard_output: false }
    }
}

pub struct RunOutput {
    /// `None`: killed by a signal (see `signal`).
    pub code: Option<i32>,
    /// The signal that ended the child, when one did.
    pub signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
    /// stdout or stderr went over `max_output`.
    pub truncated: bool,
}

/// The program could not be started (not installed, not executable).
#[derive(Debug)]
pub struct SpawnError {
    pub program: String,
    pub source: std::io::Error,
}

impl fmt::Display for SpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "spawn {}: {}", self.program, self.source)
    }
}

impl std::error::Error for SpawnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// True when `err` is a `run` spawn failure because the program does not exist (JS `ENOENT`).
pub fn is_not_found(err: &anyhow::Error) -> bool {
    err.downcast_ref::<SpawnError>().is_some_and(|e| e.source.kind() == std::io::ErrorKind::NotFound)
}

fn read_capped(mut reader: impl Read, max: usize, over: &AtomicBool) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut truncated = false;
    let mut buf = [0u8; 64 * 1024];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = max.saturating_sub(out.len());
                out.extend_from_slice(&buf[..n.min(room)]);
                if n > room {
                    truncated = true;
                    over.store(true, Ordering::Relaxed);
                }
            }
        }
    }
    (out, truncated)
}

/// Signals the child's process group (`run` and the responder start every child as the leader of its own group, so
/// grandchildren go with it).
pub fn kill_group(pid: u32, signal: i32) {
    // SAFETY: a plain signal to a process group this process created and has not given up (the leader is reaped only
    // after the callers' last use, and a group id cannot be reused while a member lives).
    unsafe { libc::kill(-(pid as libc::pid_t), signal) };
}

/// True while any process of the group `pid` leads is alive.
pub fn group_alive(pid: u32) -> bool {
    // SAFETY: signal 0 only checks that the group exists.
    unsafe { libc::kill(-(pid as libc::pid_t), 0) == 0 }
}

/// Sets `cmd` up to lead a new process group: signals sent to `-pid` reach its descendants too.
pub fn own_process_group(cmd: &mut Command) {
    cmd.process_group(0);
}

/// How long a group gets between SIGTERM and SIGKILL.
pub const TERM_GRACE: Duration = Duration::from_secs(10);

/// Runs `argv` to completion in its own process group. A program that cannot be started is an `Err` (`SpawnError`);
/// a non-zero exit or a timeout is an `Ok` the caller inspects. On timeout or when output passes `max_output` the
/// group gets SIGTERM, then SIGKILL after `TERM_GRACE`; no process of the group is left once `run` returns after that.
pub fn run(argv: &[String], opts: &RunOptions) -> Result<RunOutput> {
    let (program, args) = argv.split_first().ok_or_else(|| anyhow!("empty command"))?;
    let mut cmd = Command::new(program);
    cmd.args(args);
    own_process_group(&mut cmd);
    if let Some(cwd) = &opts.cwd {
        cmd.current_dir(cwd);
    }
    if let Some(env) = &opts.env {
        cmd.env_clear();
        cmd.envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    }
    let output = || if opts.discard_output { Stdio::null() } else { Stdio::piped() };
    cmd.stdin(if opts.stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(output()).stderr(output());
    let mut child = cmd.spawn().map_err(|source| SpawnError { program: program.clone(), source })?;

    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let max = opts.max_output;
    let pid = child.id();
    let over = AtomicBool::new(false);
    let over = &over;

    let (status, timed_out, out, err) = thread::scope(|scope| -> Result<_> {
        if let (Some(mut stdin), Some(data)) = (stdin, opts.stdin.as_deref()) {
            // The child may exit without reading everything: a broken pipe is not an error.
            scope.spawn(move || {
                let _ = stdin.write_all(data);
            });
        }
        let out = stdout.map(|s| scope.spawn(move || read_capped(s, max, over)));
        let err = stderr.map(|s| scope.spawn(move || read_capped(s, max, over)));

        let deadline = opts.timeout.map(|t| Instant::now() + t);
        let mut terminated_at: Option<Instant> = None;
        let mut timed_out = false;
        let mut killed = false;
        let mut pause = Duration::from_millis(1);
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            let now = Instant::now();
            if deadline.is_some_and(|d| now >= d) {
                timed_out = true;
            }
            if terminated_at.is_none() && (timed_out || over.load(Ordering::Relaxed)) {
                kill_group(pid, libc::SIGTERM);
                terminated_at = Some(now);
            }
            if let Some(t) = terminated_at
                && !killed
                && now >= t + TERM_GRACE
            {
                kill_group(pid, libc::SIGKILL);
                killed = true;
            }
            thread::sleep(pause);
            pause = (pause * 2).min(Duration::from_millis(25));
        };
        // The leader is gone; what it left behind in the group (it holds the pipes open) still gets its grace.
        if let Some(t) = terminated_at {
            while group_alive(pid) {
                if Instant::now() >= t + TERM_GRACE {
                    kill_group(pid, libc::SIGKILL);
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
        let out = out.map_or(Ok((Vec::new(), false)), |h| h.join().map_err(|_| anyhow!("reading stdout panicked")))?;
        let err = err.map_or(Ok((Vec::new(), false)), |h| h.join().map_err(|_| anyhow!("reading stderr panicked")))?;
        Ok((status, timed_out, out, err))
    })?;

    Ok(RunOutput { code: status.code(), signal: status.signal(), stdout: out.0, stderr: err.0, timed_out, truncated: out.1 || err.1 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> Timestamp {
        parse_time(s).unwrap_or_else(|| panic!("{s} did not parse"))
    }

    #[test]
    fn iso_is_js_to_iso_string() {
        let t: Timestamp = "2026-10-21T06:00:00Z".parse().expect("valid");
        assert_eq!(iso(t), "2026-10-21T06:00:00.000Z");
        let t: Timestamp = "2026-10-21T06:00:00.0129Z".parse().expect("valid");
        assert_eq!(iso(t), "2026-10-21T06:00:00.012Z");
        let t: Timestamp = "2026-10-21T08:30:05.5+02:00".parse().expect("valid");
        assert_eq!(iso(t), "2026-10-21T06:30:05.500Z");
    }

    #[test]
    fn parse_time_reads_iso_8601() {
        let expect = "2026-10-21T06:00:00.000Z";
        assert_eq!(iso(ts("2026-10-21T06:00:00Z")), expect);
        assert_eq!(iso(ts("2026-10-21T06:00:00.000Z")), expect);
        assert_eq!(iso(ts("2026-10-21T06:00Z")), expect);
        assert_eq!(iso(ts("2026-10-21T08:00:00+02:00")), expect);
        assert_eq!(iso(ts("2026-10-21T08:00:00+0200")), expect);
        assert_eq!(iso(ts("2026-10-20T22:30:00-07:30")), expect);
        assert_eq!(iso(ts("2026-10-21T06:00:00.123456Z")), "2026-10-21T06:00:00.123Z");
        assert_eq!(iso(ts("2026-10-21T06:00:00.5Z")), "2026-10-21T06:00:00.500Z");
        // No offset: UTC here (local time in JS).
        assert_eq!(iso(ts("2026-10-21T06:00:00")), expect);
        assert_eq!(iso(ts("2026-10-21 06:00:00")), expect);
    }

    #[test]
    fn parse_time_date_only_is_utc_midnight() {
        assert_eq!(iso(ts("2026-10-21")), "2026-10-21T00:00:00.000Z");
        assert_eq!(iso(ts("2026-10")), "2026-10-01T00:00:00.000Z");
        assert_eq!(iso(ts("2026")), "2026-01-01T00:00:00.000Z");
    }

    #[test]
    fn parse_time_reads_rfc_2822() {
        let expect = "2026-10-21T06:00:00.000Z";
        assert_eq!(iso(ts("Wed, 21 Oct 2026 06:00:00 GMT")), expect);
        assert_eq!(iso(ts("Wed, 21 Oct 2026 06:00:00 +0000")), expect);
        assert_eq!(iso(ts("Wed, 21 Oct 2026 08:00:00 +0200")), expect);
        assert_eq!(iso(ts("21 Oct 2026 06:00 UTC")), expect);
        assert_eq!(iso(ts("Tue, 20 Oct 2026 23:00:00 PDT")), expect);
        assert_eq!(iso(ts("Tue, 20 Oct 2026 22:00:00 PST")), "2026-10-21T06:00:00.000Z");
        assert_eq!(iso(ts("Tue, 20 Oct 2026 23:00:00 EST")), "2026-10-21T04:00:00.000Z");
        assert_eq!(iso(ts("Tue, 20 Oct 2026 23:00:00 CST")), "2026-10-21T05:00:00.000Z");
        assert_eq!(iso(ts("Tue, 20 Oct 2026 23:00:00 MST")), "2026-10-21T06:00:00.000Z");
        assert_eq!(iso(ts("Wed, 21 Oct 26 06:00:00 GMT")), expect);
    }

    #[test]
    fn parse_time_rejects_what_js_rejects() {
        for bad in ["", "not a date", "2026-13-01", "2026-02-30", "2026-10-21T25:00:00Z", "2026-10-21T06:61:00Z", "Wed, 32 Oct 2026 06:00:00 GMT"] {
            assert!(parse_time(bad).is_none(), "{bad:?} should not parse");
        }
        assert_eq!(iso(ts("2026-10-21T24:00:00Z")), "2026-10-22T00:00:00.000Z");
    }

    #[test]
    fn parse_time_reads_the_loose_forms_js_reads() {
        let expect = "2026-10-21T06:00:00.000Z";
        for text in [
            "2026-10-21 06:00:00 UTC",
            "2026-10-21T06:00:00 GMT",
            "Wed,21 Oct 2026 06:00:00 GMT",
            "Oct 21 2026 06:00:00",
            "October 21, 2026 06:00",
            "Wed Oct 21 2026 06:00:00 GMT+0000 (UTC)",
        ] {
            assert_eq!(iso(ts(text)), expect, "{text}");
        }
        for text in ["Oct 21, 2026", "October 21, 2026", "21 Oct 2026", "Wed, 21 Oct 2026", "Oct. 21 2026"] {
            assert_eq!(iso(ts(text)), "2026-10-21T00:00:00.000Z", "{text}");
        }
    }

    #[test]
    fn local_date_uses_the_zone_and_falls_back_to_utc() {
        let t = ts("2026-10-21T23:30:00Z");
        assert_eq!(local_date(t, "Europe/London"), "2026-10-22");
        assert_eq!(local_date(t, "America/Los_Angeles"), "2026-10-21");
        assert_eq!(local_date(t, "Not/AZone"), "2026-10-21");
    }

    #[test]
    fn local_date_reads_utc_offsets() {
        let t = ts("2026-10-21T23:30:00Z");
        assert_eq!(local_date(t, "+01:00"), "2026-10-22");
        assert_eq!(local_date(t, "+0100"), "2026-10-22");
        assert_eq!(local_date(t, "-02:00"), "2026-10-21");
        assert_eq!(local_date(t, "+25:00"), "2026-10-21");
    }

    #[test]
    fn base64_round_trips_and_ignores_whitespace() {
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_decode("Zm9v\nYmE=\n").expect("decodes"), b"fooba");
        assert_eq!(base64_decode("Zm9vYg").expect("decodes"), b"foob");
        assert!(base64_decode("Zm9v!").is_err());
    }

    #[test]
    fn sha256_matches_the_known_vector() {
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn parallel_map_keeps_order() {
        let items: Vec<u32> = (0..50).collect();
        assert_eq!(parallel_map(&items, 4, |n| n * 2), (0..50).map(|n| n * 2).collect::<Vec<_>>());
        assert!(parallel_map(&Vec::<u32>::new(), 4, |n| *n).is_empty());
    }

    #[test]
    fn run_feeds_stdin_and_reports_exit_and_missing_programs() {
        let out = run(&["cat".into()], &RunOptions { stdin: Some(b"hello".to_vec()), ..Default::default() }).expect("cat runs");
        assert_eq!((out.code, out.stdout.as_slice(), out.timed_out), (Some(0), &b"hello"[..], false));
        let out =
            run(&["sh".into(), "-c".into(), "echo $FOO; exit 3".into()], &RunOptions { env: Some(vec![("FOO".into(), "bar".into())]), ..Default::default() })
                .expect("sh runs");
        assert_eq!((out.code, out.stdout.as_slice()), (Some(3), &b"bar\n"[..]));
        let err = run(&["cvecondor-no-such-program".into()], &RunOptions::default()).err().expect("spawn fails");
        assert!(is_not_found(&err));
    }

    #[test]
    fn run_terminates_on_timeout_and_caps_output() {
        let out = run(&["sleep".into(), "30".into()], &RunOptions { timeout: Some(Duration::from_millis(100)), ..Default::default() }).expect("sleep runs");
        assert!(out.timed_out);
        assert_eq!(out.code, None);
        let out = run(&["sh".into(), "-c".into(), "yes | head -c 100000".into()], &RunOptions { max_output: 1000, ..Default::default() }).expect("sh runs");
        assert_eq!(out.stdout.len(), 1000);
        assert!(out.truncated);
    }

    #[test]
    fn run_signals_the_whole_process_group_on_timeout() {
        // `sleep` is a grandchild of the program `run` started: it must not outlive the run.
        let started = Instant::now();
        let out = run(&["sh".into(), "-c".into(), "sleep 30 & echo $!; wait".into()], &RunOptions { timeout: Some(Duration::from_millis(300)), ..Default::default() })
            .expect("sh runs");
        assert!(out.timed_out);
        assert!(started.elapsed() < Duration::from_secs(8));
        let grandchild: i32 = String::from_utf8_lossy(&out.stdout).trim().parse().expect("the grandchild pid");
        let gone = (0..300).any(|_| {
            // SAFETY: signal 0 only probes whether the process exists.
            let alive = unsafe { libc::kill(grandchild, 0) } == 0;
            if alive {
                thread::sleep(Duration::from_millis(10));
            }
            !alive
        });
        assert!(gone, "grandchild {grandchild} is still running");
    }

    #[test]
    fn run_stops_the_child_as_soon_as_output_passes_the_cap() {
        let started = Instant::now();
        let out = run(&["sh".into(), "-c".into(), "head -c 100000 /dev/zero; sleep 30".into()], &RunOptions { max_output: 1000, ..Default::default() })
            .expect("sh runs");
        assert!(out.truncated);
        assert_eq!(out.stdout.len(), 1000);
        assert!(started.elapsed() < Duration::from_secs(8), "the child kept running for {:?}", started.elapsed());
    }

    #[test]
    fn run_with_discarded_output_does_not_wait_for_background_processes() {
        let started = Instant::now();
        let out = run(&["sh".into(), "-c".into(), "sleep 6 & exit 0".into()], &RunOptions { discard_output: true, ..Default::default() }).expect("sh runs");
        assert_eq!((out.code, out.signal), (Some(0), None));
        assert!(started.elapsed() < Duration::from_secs(3));
        let out = run(&["sh".into(), "-c".into(), "kill -TERM $$".into()], &RunOptions::default()).expect("sh runs");
        assert_eq!((out.code, out.signal), (None, Some(libc::SIGTERM)));
    }
}
