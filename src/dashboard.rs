// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! `dashboard`: what `status`, `secrets` and `inbox --peek` say, as one static HTML page for a person to read.
//!
//! Read-only on purpose. Nothing listens and nothing is fetched: the command reads the state dir and prints the page, so
//! a headless watcher is reached the way it always is (`ssh web1 docker exec cvecondor cvecondor dashboard > page.html`).
//! The page has no script and loads nothing (a CSP says so), every string from the state is escaped, and the state only
//! holds names and fingerprints, never values; the config's own secret values are scrubbed from the text as well.
//! Judgment and every change stay with the agent.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use indexmap::IndexSet;

use crate::cli::{Overview, ago, case_tags, classifier_text, clip, handled_text, responder_text, services_down, source_error_text};
use crate::config::{Config, redact};
use crate::fixes::describe_wait;
use crate::inbox::{InboxEntry, unread};
use crate::name::{NAME, VERSION};
use crate::notify::{helo_name, notifier_lines};
use crate::types::Inventory;
use crate::util::{self, iso, parse_time};
use crate::vendors::detect_vendors;
use crate::watch::{Case, CaseStatus};

/// How many rows a long list shows before it says how many more there are.
const ROWS: usize = 100;
/// Inbox items shown, newest first.
const INBOX_ROWS: usize = 20;
/// A cycle older than this many poll intervals means the watcher is not running.
const STALE_AFTER_POLLS: f64 = 3.0;

const STYLE: &str = "\
:root{color-scheme:light dark;--fg:#1b1b1b;--bg:#fff;--muted:#595959;--line:#c8c8c8;--bad:#a40000}
@media (prefers-color-scheme:dark){:root{--fg:#e6e6e6;--bg:#161616;--muted:#a3a3a3;--line:#444;--bad:#ff8a80}}
*{box-sizing:border-box}
body{margin:0 auto;padding:1rem;max-width:64rem;font:16px/1.45 system-ui,-apple-system,\"Segoe UI\",sans-serif;color:var(--fg);background:var(--bg)}
h1{font-size:1.4rem;margin:0 0 .25rem}
h2{font-size:1.15rem;margin:2rem 0 .5rem;padding-bottom:.2rem;border-bottom:1px solid var(--line)}
h3{font-size:1rem;margin:0 0 .25rem;overflow-wrap:anywhere}
p{margin:.4rem 0}
a{color:inherit}
code,pre{font:.9em ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:.4rem 0}
.muted{color:var(--muted)}
.bad{color:var(--bad);font-weight:600}
.scroll{overflow-x:auto}
table{border-collapse:collapse;min-width:min(100%,32rem)}
th,td{text-align:left;vertical-align:top;padding:.25rem .6rem .25rem 0;border-bottom:1px solid var(--line)}
th{font-weight:600}
td{overflow-wrap:break-word}
td:first-child{white-space:nowrap}
article{margin:0 0 1rem;padding:0 0 .75rem;border-bottom:1px solid var(--line)}
dl{margin:.25rem 0;display:grid;grid-template-columns:max-content 1fr;gap:.1rem .75rem}
dt{color:var(--muted)}
dd{margin:0;overflow-wrap:anywhere}
ul{margin:.2rem 0;padding-left:1.2rem}
summary{cursor:pointer;margin:.5rem 0}
@media (max-width:40rem){dl{grid-template-columns:1fr}dd{margin-bottom:.3rem}}
@media print{body{max-width:none}}
";

/// `&`, `<`, `>`, `"` and `'` as entities; control characters other than newline and tab dropped.
fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '\n' | '\t' => out.push(c),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Whether `url` may become a link: http or https, one token, nothing a browser would read differently.
fn safe_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    (lower.starts_with("https://") || lower.starts_with("http://")) && url.len() <= 2000 && !url.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// An 8-hex fingerprint as the state holds it; anything else is not shown.
fn fingerprint(fp: Option<&str>) -> String {
    match fp {
        Some(fp) if fp.len() == 8 && fp.chars().all(|c| c.is_ascii_hexdigit()) => format!("<code>{fp}</code>"),
        Some(_) => "?".to_string(),
        None => "-".to_string(),
    }
}

struct Page<'a> {
    config: &'a Config,
}

impl Page<'_> {
    /// Text from the state, ready for HTML: the config's secret values scrubbed, then escaped.
    fn t(&self, text: &str) -> String {
        esc(&redact(self.config, text))
    }

    fn code(&self, text: &str) -> String {
        format!("<code>{}</code>", self.t(text))
    }

    /// A link to an advisory when it is an http(s) URL, else the text alone.
    fn link(&self, url: &str) -> String {
        let shown = self.t(url);
        if safe_url(url) && redact(self.config, url) == url { format!("<a href=\"{shown}\" rel=\"noreferrer\">{shown}</a>") } else { shown }
    }

    fn table(&self, head: &[&str], rows: &[Vec<String>]) -> String {
        let mut out = String::from("<div class=\"scroll\"><table>\n<thead><tr>");
        for h in head {
            let _ = write!(out, "<th>{h}</th>");
        }
        out.push_str("</tr></thead>\n<tbody>\n");
        for row in rows.iter().take(ROWS) {
            out.push_str("<tr>");
            for cell in row {
                let _ = write!(out, "<td>{cell}</td>");
            }
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n");
        if rows.len() > ROWS {
            let _ = writeln!(out, "<p class=\"muted\">… {} more</p>", rows.len() - ROWS);
        }
        out
    }

    /// How serious a case is for the user, in words: the responder's rating when it gave one, else the watcher's first.
    fn rating(&self, c: &Case) -> String {
        match (c.triage.as_ref().and_then(|t| t.rating.as_deref()).filter(|r| !r.is_empty()), c.assessment.as_ref()) {
            (Some(r), _) => clip(r, 60),
            (None, Some(a)) => a.rating.as_str().to_string(),
            (None, None) => "unrated".to_string(),
        }
    }

    fn case(&self, c: &Case, overview: &Overview) -> String {
        let status = c.status();
        let mut out = format!("<article>\n<h3><strong>{}</strong> {} {}</h3>\n", self.t(&self.rating(c)), self.code(&c.key), self.t(&clip(&c.title, 200)));
        let state = match status {
            CaseStatus::Waiting => c.status_reason().map_or_else(|| "waiting".to_string(), |r| format!("waiting on {}: {}", r.as_str(), c.status_detail())),
            _ => format!("{}, {}", status.as_str(), c.state.as_str()),
        };
        let _ = writeln!(
            out,
            "<p class=\"muted\">{}{} · {} · updated {}</p>\n<dl>",
            self.t(&state),
            self.t(&handled_text(c)),
            self.t(&case_tags(c)),
            self.t(&ago(Some(&c.updated_at)))
        );
        let mut row = |name: &str, value: String| {
            if !value.is_empty() {
                let _ = writeln!(out, "<dt>{name}</dt><dd>{value}</dd>");
            }
        };
        let why = c.assessment.as_ref().map(|a| a.why.as_str()).unwrap_or_default();
        row("Why", self.t(why));
        if c.reason != why {
            row("Reason", self.t(&c.reason));
        }
        let mut applies: Vec<String> = c.places.iter().map(|p| format!("{} {}", self.code(&p.r#where), self.t(&format!("({})", p.host)))).collect();
        match c.affected.as_deref().filter(|a| !a.is_empty()) {
            Some(affected) => applies.extend(affected.iter().take(8).map(|a| {
                format!(
                    "{} {} {}{}",
                    self.t(&a.name),
                    self.t(&a.version),
                    self.t(&format!("at {}", a.r#where)),
                    if a.running == Some(false) { " (stopped)" } else { "" }
                )
            })),
            None => applies.extend(c.targets.iter().take(8).map(|t| self.t(t))),
        }
        row("Applies to", list(&applies));
        let mut done: Vec<String> = Vec::new();
        if let Some(t) = &c.triage {
            let path = serde_json::to_value(t.path).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
            done.push(self.t(&format!("{path}: {}", t.why)));
        }
        done.extend(c.pull_requests.iter().flatten().map(|pr| format!("pull request {}", self.link(pr))));
        if let Some(report) = c.report.as_deref().filter(|r| !r.is_empty()) {
            done.push(format!("report {}", self.code(report)));
        }
        if let Some(entry) = overview.queue.entries.get(&c.key) {
            done.push(self.t(&format!("queued to retry after {} (attempt {}): {}", entry.next_at, entry.attempts + 1, entry.reason)));
        } else if let Some(error) = c.dispatch_error.as_deref().filter(|e| !e.is_empty()) {
            done.push(self.t(&format!("dispatch failed: {error}")));
        }
        row("Done or proposed", list(&done));
        let waits: Vec<String> = c.waiting_for.iter().flatten().take(8).map(|w| self.t(&describe_wait(w))).collect();
        row("Waiting for", list(&waits));
        let urls: Vec<String> = c.urls.iter().take(5).map(|u| self.link(u)).collect();
        row("Advisories", list(&urls));
        out.push_str("</dl>\n</article>\n");
        out
    }

    fn cases(&self, overview: &Overview) -> String {
        let (open, waiting, closed) = (overview.by_status(CaseStatus::Open), overview.by_status(CaseStatus::Waiting), overview.by_status(CaseStatus::Closed));
        let mut out = String::from("<section>\n<h2>Cases</h2>\n");
        if overview.cases.is_empty() {
            out.push_str("<p>No cases yet.</p>\n</section>\n");
            return out;
        }
        let mut ratings: Vec<(String, usize)> = Vec::new();
        for c in open.iter().chain(&waiting) {
            let label = self.rating(c);
            match ratings.iter_mut().find(|(l, _)| *l == label) {
                Some((_, n)) => *n += 1,
                None => ratings.push((label, 1)),
            }
        }
        let _ = write!(out, "<p>{} open, {} waiting, {} closed.", open.len(), waiting.len(), closed.len());
        if !ratings.is_empty() {
            let _ = write!(out, " Open and waiting: {}.", ratings.iter().map(|(l, n)| self.t(&format!("{n} {l}"))).collect::<Vec<_>>().join(", "));
        }
        out.push_str("</p>\n");
        for (name, list) in [("Open", &open), ("Waiting", &waiting)] {
            if list.is_empty() {
                continue;
            }
            let _ = writeln!(out, "<h3>{name}</h3>");
            for c in list.iter().take(ROWS) {
                out.push_str(&self.case(c, overview));
            }
            if list.len() > ROWS {
                let _ = writeln!(out, "<p class=\"muted\">… {} more</p>", list.len() - ROWS);
            }
        }
        if !closed.is_empty() {
            let rows: Vec<Vec<String>> = closed
                .iter()
                .map(|c| {
                    vec![
                        self.code(&c.key),
                        self.t(&c.status_reason().map_or_else(|| "closed".to_string(), |r| r.as_str().to_string())),
                        self.t(&clip(&c.title, 120)),
                        self.t(handled_text(c).trim().trim_matches(['(', ')'])),
                        self.t(&ago(Some(&c.updated_at))),
                    ]
                })
                .collect();
            let _ = write!(
                out,
                "<details>\n<summary>Closed ({})</summary>\n{}</details>\n",
                closed.len(),
                self.table(&["Case", "Why", "Title", "Handled", "Updated"], &rows)
            );
        }
        out.push_str("</section>\n");
        out
    }

    fn health(&self, overview: &Overview) -> String {
        let mut out = String::from("<section>\n<h2>Health</h2>\n<dl>\n");
        let last = match &overview.last {
            Some(l) => {
                let mut text = format!("{} ({}), {} ms, {} polled, {} new", self.t(&l.at), self.t(&ago(Some(&l.at))), l.duration_ms, l.polled, l.fresh);
                if !l.errors.is_empty() {
                    let _ = write!(text, "<br><span class=\"bad\">errors:</span> {}", self.t(&l.errors.iter().take(6).cloned().collect::<Vec<_>>().join("; ")));
                }
                text
            }
            None => "none yet".to_string(),
        };
        let _ = writeln!(out, "<dt>Last cycle</dt><dd>{last}</dd>");
        let failing = overview.failing_sources();
        let mut sources = format!("{} known, {} failing", overview.feeds.len(), failing.len());
        if !failing.is_empty() {
            let _ = write!(sources, ": {}", self.t(&failing.iter().take(8).map(|(id, f)| source_error_text(id, f)).collect::<Vec<_>>().join("; ")));
        }
        let _ = writeln!(out, "<dt>Sources</dt><dd>{sources}</dd>");
        if let Some(inventory) = &overview.inventory {
            let down = services_down(self.config, inventory);
            if !down.is_empty() {
                let _ = writeln!(out, "<dt>Services down</dt><dd>{}</dd>", self.t(&down.join("; ")));
            }
        }
        if !overview.queue.entries.is_empty() {
            let next = overview.queue.entries.values().map(|e| e.next_at.as_str()).min().unwrap_or_default();
            let paused = overview
                .queue
                .paused_until
                .as_deref()
                .filter(|_| overview.queue.paused(util::now()))
                .map(|t| format!("; the agent is out of quota until {t}"))
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "<dt>Retry queue</dt><dd>{}</dd>",
                self.t(&format!("{} case(s) waiting for another responder run, the next not before {next}{paused}", overview.queue.entries.len()))
            );
        }
        let _ = writeln!(
            out,
            "<dt>Classifier</dt><dd>{}</dd>\n<dt>Responder</dt><dd>{}</dd>",
            self.t(&classifier_text(self.config)),
            self.t(&responder_text(self.config))
        );
        out.push_str("</dl>\n");
        // The heading says "Notifiers"; the status text's own "Notifiers:" prefix is dropped.
        let lines: Vec<String> = notifier_lines(self.config, util::now())
            .into_iter()
            .filter_map(|l| match l.strip_prefix("Notifiers:").map(str::trim) {
                Some("") => None,
                Some(rest) => Some(rest.to_string()),
                None => Some(l),
            })
            .collect();
        let _ = writeln!(out, "<h3>Notifiers</h3>\n<pre>{}</pre>", self.t(&lines.join("\n")));
        out.push_str("<h3>Collectors</h3>\n");
        match overview.inventory.as_ref().filter(|i| !i.sources.is_empty()) {
            Some(inventory) => {
                let rows: Vec<Vec<String>> = inventory
                    .sources
                    .iter()
                    .map(|(name, s)| {
                        let mut note = s.error.as_deref().filter(|e| !e.is_empty()).map(|e| self.t(e)).unwrap_or_default();
                        for w in s.warnings.iter().flatten() {
                            if !note.is_empty() {
                                note.push_str("<br>");
                            }
                            note.push_str(&self.t(&format!("warning: {w}")));
                        }
                        vec![
                            self.code(name),
                            if s.ok { "ok".to_string() } else { "<span class=\"bad\">FAIL</span>".to_string() },
                            s.items.to_string(),
                            s.secrets.to_string(),
                            self.t(&ago(Some(&s.at))),
                            note,
                        ]
                    })
                    .collect();
                out.push_str(&self.table(&["Collector", "State", "Items", "Secrets", "Read", "Notes"], &rows));
            }
            None => out.push_str("<p>No collector has run yet.</p>\n"),
        }
        out.push_str("</section>\n");
        out
    }

    fn inventory(&self, inventory: Option<&Inventory>) -> String {
        let mut out = String::from("<section>\n<h2>Inventory</h2>\n");
        let Some(inventory) = inventory else {
            out.push_str("<p>Not collected yet.</p>\n</section>\n");
            return out;
        };
        let _ = writeln!(
            out,
            "<p>{} items, {} services, {} secret findings, {} vendor signals. Collected {} ({}).</p>",
            inventory.items.len(),
            inventory.services.len(),
            inventory.secrets.len(),
            inventory.signals.len(),
            self.t(&inventory.collected_at),
            self.t(&ago(Some(&inventory.collected_at)))
        );
        let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
        let mut places: BTreeMap<(&str, &str), (usize, IndexSet<&str>)> = BTreeMap::new();
        for item in &inventory.items {
            *kinds.entry(item.kind.as_str()).or_default() += 1;
            let place = places.entry((item.host.as_str(), item.r#where.as_str())).or_default();
            place.0 += 1;
            place.1.insert(item.kind.as_str());
        }
        if !inventory.items.is_empty() {
            let rows: Vec<Vec<String>> = kinds.iter().map(|(kind, n)| vec![self.t(kind), n.to_string()]).collect();
            out.push_str("<h3>Items by kind</h3>\n");
            out.push_str(&self.table(&["Kind", "Items"], &rows));
            let rows: Vec<Vec<String>> = places
                .iter()
                .map(|((host, place), (n, of))| vec![self.t(host), self.code(place), n.to_string(), self.t(&of.iter().copied().collect::<Vec<_>>().join(", "))])
                .collect();
            out.push_str("<h3>Items by place</h3>\n");
            out.push_str(&self.table(&["Host", "Place", "Items", "Kinds"], &rows));
        }
        if !inventory.services.is_empty() {
            let rows: Vec<Vec<String>> = inventory
                .services
                .iter()
                .map(|s| {
                    vec![
                        self.t(&s.host),
                        self.code(&s.r#where),
                        self.t(s.image.as_deref().unwrap_or("-")),
                        self.t(&s.state),
                        self.t(&if s.exposed.is_empty() { "-".to_string() } else { s.exposed.join(", ") }),
                    ]
                })
                .collect();
            out.push_str("<h3>Services</h3>\n");
            out.push_str(&self.table(&["Host", "Service", "Image", "State", "Exposed"], &rows));
        }
        let vendors = detect_vendors(inventory, self.config);
        if !vendors.is_empty() {
            let rows: Vec<Vec<String>> = vendors
                .iter()
                .map(|v| {
                    vec![
                        format!("{}{}", self.t(&v.name), if v.manual { " (config)" } else { "" }),
                        self.code(&v.id),
                        self.t(&v.evidence.iter().take(4).cloned().collect::<Vec<_>>().join("; ")),
                    ]
                })
                .collect();
            out.push_str("<h3>Vendors</h3>\n");
            out.push_str(&self.table(&["Vendor", "Id", "Seen from"], &rows));
        }
        out.push_str("</section>\n");
        out
    }

    fn secrets(&self, inventory: Option<&Inventory>) -> String {
        let mut out = String::from("<section>\n<h2>Secrets</h2>\n");
        let findings = inventory.map(|i| i.secrets.as_slice()).unwrap_or_default();
        if findings.is_empty() {
            out.push_str("<p>No secret findings.</p>\n</section>\n");
            return out;
        }
        out.push_str("<p class=\"muted\">Names, places and fingerprints (the first 8 hex of a value's SHA-256). Values are never stored or shown.</p>\n");
        let rows: Vec<Vec<String>> = findings
            .iter()
            .map(|s| {
                let location = match s.line.filter(|l| *l != 0) {
                    Some(line) => format!("{}:{line}", s.location),
                    None => s.location.clone(),
                };
                vec![
                    self.t(s.name.as_deref().unwrap_or(&s.kind)),
                    format!("{} {}", self.code(&s.r#where), self.t(&format!("({})", s.host))),
                    self.t(&location),
                    self.t(s.exposure.as_str()),
                    fingerprint(s.fingerprint.as_deref()),
                ]
            })
            .collect();
        out.push_str(&self.table(&["Name", "Place", "Location", "Exposure", "Fingerprint"], &rows));
        out.push_str("</section>\n");
        out
    }

    fn inbox(&self, dir: &Path, entries: &[InboxEntry], unread_count: usize) -> String {
        let mut out = String::from("<section>\n<h2>Inbox</h2>\n");
        if entries.is_empty() {
            out.push_str("<p>Nothing kept yet.</p>\n</section>\n");
            return out;
        }
        let _ = writeln!(
            out,
            "<p>{unread_count} unread of {}. Showing the latest {}; this page does not mark anything read (<code>{NAME} inbox</code> does).</p>",
            entries.len(),
            entries.len().min(INBOX_ROWS)
        );
        let reports = dir.join("reports");
        let rows: Vec<Vec<String>> = entries
            .iter()
            .rev()
            .take(INBOX_ROWS)
            .map(|e| {
                let file = Path::new(&e.file);
                // The file's name when it lives under reports/ (the usual), else the path as kept.
                let shown = file.strip_prefix(&reports).ok().and_then(Path::to_str).unwrap_or(&e.file);
                vec![self.t(&e.at), self.t(&e.event), self.t(&clip(&e.title, 200)), self.code(shown)]
            })
            .collect();
        out.push_str(&self.table(&["At", "Event", "Title", "File"], &rows));
        out.push_str("</section>\n");
        out
    }

    fn reports(&self, dir: &Path) -> String {
        let reports = dir.join("reports");
        let mut names: Vec<String> =
            fs::read_dir(&reports).map(|d| d.filter_map(Result::ok).map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
        names.sort_by(|a, b| b.cmp(a));
        let mut out = String::from("<section>\n<h2>Reports</h2>\n");
        if names.is_empty() {
            out.push_str("<p>No reports yet.</p>\n</section>\n");
            return out;
        }
        let _ = writeln!(
            out,
            "<p>{} file(s) in {}, newest first. Open them on the watcher; none is inlined here.</p>\n<ul>",
            names.len(),
            self.code(&reports.to_string_lossy())
        );
        for name in names.iter().take(ROWS) {
            let _ = writeln!(out, "<li>{}</li>", self.code(name));
        }
        out.push_str("</ul>\n");
        if names.len() > ROWS {
            let _ = writeln!(out, "<p class=\"muted\">… {} more</p>", names.len() - ROWS);
        }
        out.push_str("</section>\n");
        out
    }
}

/// One item as text, several as a list.
fn list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        many => format!("<ul>{}</ul>", many.iter().map(|i| format!("<li>{i}</li>")).collect::<String>()),
    }
}

/// What is wrong, in a few words each: empty when the watcher looks healthy.
fn problems(config: &Config, overview: &Overview) -> Vec<String> {
    let mut problems = Vec::new();
    match &overview.last {
        None => problems.push("no cycle has run yet".to_string()),
        Some(l) => {
            let age = parse_time(&l.at).map(|t| (util::now().as_millisecond() - t.as_millisecond()) as f64 / 60_000.0);
            if age.is_none_or(|m| m > config.poll_minutes * STALE_AFTER_POLLS) {
                problems.push(format!("last cycle {} (every {} min)", ago(Some(&l.at)), config.poll_minutes));
            }
            if !l.errors.is_empty() {
                problems.push(format!("{} error(s) in the last cycle", l.errors.len()));
            }
        }
    }
    let failing = overview.failing_sources().len();
    if failing > 0 {
        problems.push(format!("{failing} source(s) failing"));
    }
    if let Some(inventory) = &overview.inventory {
        let collectors = inventory.sources.values().filter(|s| !s.ok).count();
        if collectors > 0 {
            problems.push(format!("{collectors} collector(s) failing"));
        }
        let down = services_down(config, inventory).len();
        if down > 0 {
            problems.push(format!("{down} service(s) down"));
        }
    }
    if !overview.queue.entries.is_empty() {
        problems.push(format!("{} case(s) in the retry queue", overview.queue.entries.len()));
    }
    problems
}

/// The whole page, from the state dir only.
pub fn render(config: &Config) -> String {
    let dir = &config.state_dir;
    let overview = Overview::load(dir);
    let page = Page { config };
    let entries = unread(dir, true).unwrap_or_default();
    let unread_count = unread(dir, false).map_or(0, |u| u.len());
    let empty = overview.last.is_none() && overview.inventory.is_none() && overview.cases.is_empty() && overview.feeds.is_empty();
    let problems = problems(config, &overview);
    let summary = if empty {
        "Nothing yet: no cycle has run and no inventory has been collected in this state directory.".to_string()
    } else if problems.is_empty() {
        let last = overview.last.as_ref().map_or_else(String::new, |l| ago(Some(&l.at)));
        format!("<strong>Healthy.</strong> Last cycle {}; no failing source or collector.", page.t(&last))
    } else {
        format!("<span class=\"bad\">Needs attention:</span> {}.", page.t(&problems.join("; ")))
    };
    let mut html = String::with_capacity(32 * 1024);
    let _ = write!(
        html,
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">\n\
         <meta name=\"referrer\" content=\"no-referrer\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta name=\"color-scheme\" content=\"light dark\">\n<title>{NAME} dashboard</title>\n<style>\n{STYLE}</style>\n</head>\n<body>\n\
         <header>\n<h1>{NAME} dashboard</h1>\n<p class=\"muted\">Generated {} on {} · {NAME} {VERSION} · read-only snapshot of the state directory</p>\n<p>{summary}</p>\n",
        iso(util::now()),
        page.t(&helo_name()),
    );
    if !overview.cases.is_empty() || unread_count > 0 {
        let count = |s| overview.by_status(s).len();
        let _ = writeln!(
            html,
            "<p>Cases: {} open, {} waiting, {} closed. Inbox: {unread_count} unread.</p>",
            count(CaseStatus::Open),
            count(CaseStatus::Waiting),
            count(CaseStatus::Closed)
        );
    }
    html.push_str("</header>\n<main>\n");
    html.push_str(&page.health(&overview));
    html.push_str(&page.cases(&overview));
    html.push_str(&page.inventory(overview.inventory.as_ref()));
    html.push_str(&page.secrets(overview.inventory.as_ref()));
    html.push_str(&page.inbox(dir, &entries, unread_count));
    html.push_str(&page.reports(dir));
    html.push_str("</main>\n</body>\n</html>\n");
    html
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn esc_escapes_the_five_characters_and_drops_control_characters() {
        assert_eq!(esc(r#"<a href="x" onclick='y'>&"#), "&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;");
        assert_eq!(esc("a\u{1b}[31mb\u{0}\nc\td"), "a[31mb\nc\td");
    }

    #[test]
    fn only_plain_http_urls_become_links() {
        assert!(safe_url("https://nvd.nist.gov/vuln/detail/CVE-2026-1"));
        assert!(safe_url("HTTP://example.com/x"));
        for bad in ["javascript:alert(1)", "data:text/html,x", "file:///etc/passwd", "//evil.example", "https://a b", "https://a\nb", "ftp://x", ""] {
            assert!(!safe_url(bad), "{bad}");
        }
    }

    #[test]
    fn a_fingerprint_is_eight_hex_or_nothing() {
        assert_eq!(fingerprint(Some("a1b2c3d4")), "<code>a1b2c3d4</code>");
        assert_eq!(fingerprint(Some("sk-or-v1-0123456789abcdef")), "?");
        assert_eq!(fingerprint(None), "-");
    }
}
