// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! Secrets that could be compromised: where they sit, what kind, why at risk.
//! Detection is gitleaks (MIT, ~200 maintained provider rules, git history and
//! stdin modes). A secret's value never leaves this module: gitleaks' JSON is
//! read from its stdout, each value becomes an 8-hex fingerprint, and the value
//! is dropped before anything is stored, logged or sent.

use std::fmt;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::util::{self, RunOptions, js_regex, js_trim};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Exposure {
    /// In a repo's git history (any branch or tag), even if since deleted.
    GitHistory,
    /// A committed `.env` (or similar) file, whatever it holds.
    CommittedEnvFile,
    /// In a file on the default branch of a repo.
    RepoFile,
    /// A config or env file on a host (compose `.env`, compose YAML with inline values), with its permissions.
    HostFile,
    /// A container's environment: readable by anyone with Docker access and by every process in it. Listed for breach impact.
    ContainerEnv,
    /// Printed into a container's logs.
    Log,
    /// A GitHub Actions secret (name only: GitHub never reveals values). Listed for breach impact.
    CiSecret,
}

impl Exposure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GitHistory => "git-history",
            Self::CommittedEnvFile => "committed-env-file",
            Self::RepoFile => "repo-file",
            Self::HostFile => "host-file",
            Self::ContainerEnv => "container-env",
            Self::Log => "log",
            Self::CiSecret => "ci-secret",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretFinding {
    pub host: String,
    /// Same `where` as inventory items: `repo:<owner>/<name>`, `host`, `container:<name>`.
    pub r#where: String,
    /// File path (repo-relative for repos), `env`, `logs` or `actions`.
    pub location: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// Short commit id for git-history findings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// gitleaks rule id (`aws-access-token`, `generic-api-key`), or `env-var`, `env-file`, `actions-secret`.
    pub kind: String,
    /// The variable or key name when one is visible (`OPENAI_API_KEY`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// First 8 hex of the value's SHA-256: the same secret in two places has the same fingerprint. Absent when only a name is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    pub exposure: Exposure,
    /// One line: why it is at risk.
    pub risk: String,
    /// Services it likely unlocks, from the rule and the name (`openai`, `aws`, `github`, `railway`).
    #[serde(default)]
    pub providers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GitleaksHit {
    pub rule: String,
    pub description: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub commit: Option<String>,
    pub date: Option<String>,
    /// `NAME` from `NAME=…` / `name: …` in the match, when present.
    pub name: Option<String>,
    pub fingerprint: String,
}

/// One finding in gitleaks' JSON report (`--report-format json`), values included: it is read
/// from gitleaks' stdout and reduced to a `GitleaksHit` before anything is stored.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RawHit {
    #[serde(rename = "RuleID", default)]
    pub rule_id: String,
    #[serde(rename = "Description", default)]
    pub description: Option<String>,
    #[serde(rename = "Match", default)]
    pub r#match: Option<String>,
    #[serde(rename = "Secret", default)]
    pub secret: Option<String>,
    #[serde(rename = "File", default)]
    pub file: Option<String>,
    #[serde(rename = "StartLine", default)]
    pub start_line: Option<u32>,
    #[serde(rename = "Commit", default)]
    pub commit: Option<String>,
    #[serde(rename = "Date", default)]
    pub date: Option<String>,
}

/// gitleaks is not on this machine: secret scanning is skipped with this warning.
#[derive(Debug, Clone, Copy, Default)]
pub struct GitleaksMissing;

impl fmt::Display for GitleaksMissing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("gitleaks is not installed: secret scanning skipped (https://github.com/gitleaks/gitleaks, MIT)")
    }
}

impl std::error::Error for GitleaksMissing {}

/// First 8 hex of the value's SHA-256. The only form in which a secret value leaves this module.
pub fn fingerprint(value: &str) -> String {
    util::sha256_hex(value.as_bytes())[..8].to_string()
}

/// Identity of a finding across cycles: where it sits, what it is and which value (by fingerprint) it holds.
pub fn finding_key(f: &SecretFinding) -> String {
    [
        f.host.as_str(),
        f.r#where.as_str(),
        f.location.as_str(),
        f.kind.as_str(),
        f.name.as_deref().unwrap_or(""),
        f.fingerprint.as_deref().unwrap_or(""),
        f.commit.as_deref().unwrap_or(""),
    ]
    .join("\0")
}

// Lowercase tokens that name a provider in a gitleaks rule id or an env var name.
const PROVIDERS: &[(&str, &[&str])] = &[
    ("aws", &["aws", "amazon"]),
    ("gcp", &["gcp", "google", "firebase"]),
    ("azure", &["azure"]),
    ("github", &["github", "gh"]),
    ("gitlab", &["gitlab"]),
    ("bitbucket", &["bitbucket"]),
    ("openai", &["openai"]),
    ("anthropic", &["anthropic", "claude"]),
    ("openrouter", &["openrouter"]),
    ("huggingface", &["huggingface", "hf"]),
    ("stripe", &["stripe"]),
    ("paypal", &["paypal"]),
    ("slack", &["slack"]),
    ("discord", &["discord"]),
    ("telegram", &["telegram"]),
    ("twilio", &["twilio"]),
    ("sendgrid", &["sendgrid"]),
    ("mailgun", &["mailgun"]),
    ("postmark", &["postmark"]),
    ("resend", &["resend"]),
    ("cloudflare", &["cloudflare", "cf"]),
    ("digitalocean", &["digitalocean", "do"]),
    ("hetzner", &["hetzner"]),
    ("heroku", &["heroku"]),
    ("railway", &["railway"]),
    ("vercel", &["vercel"]),
    ("netlify", &["netlify"]),
    ("fly", &["fly", "flyio"]),
    ("render", &["render"]),
    ("supabase", &["supabase"]),
    ("neon", &["neon"]),
    ("planetscale", &["planetscale"]),
    ("npm", &["npm"]),
    ("pypi", &["pypi"]),
    ("docker", &["docker", "dockerhub"]),
    ("datadog", &["datadog"]),
    ("sentry", &["sentry"]),
    ("shopify", &["shopify"]),
    ("twitter", &["twitter", "x"]),
    ("database", &["postgres", "postgresql", "pg", "mysql", "mariadb", "mongo", "mongodb", "redis", "database", "db"]),
    ("jwt", &["jwt"]),
    ("smtp", &["smtp", "mail"]),
];

/// Providers a secret likely unlocks, from its rule id and variable name.
pub fn providers_of(kind: &str, name: Option<&str>) -> Vec<String> {
    let text = format!("{kind} {}", name.unwrap_or("")).to_lowercase();
    let tokens: Vec<&str> = text.split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit())).filter(|t| !t.is_empty()).collect();
    PROVIDERS.iter().filter(|(_, words)| words.iter().any(|word| tokens.contains(word))).map(|(provider, _)| (*provider).to_string()).collect()
}

static SECRET_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(^|_)(KEY|APIKEY|TOKEN|SECRET|SECRETS|PASSWORD|PASSWD|PASS|PWD|CREDENTIALS?|PRIVATE|AUTH|DSN|SALT|COOKIE|SESSION)(_|$)|(^|_)DATABASE_URL$|_URI$|_URL$")
        .expect("SECRET_NAME is a valid regex")
});

// Booleans, numbers, credential-free URLs, and references to another variable (`${DB_PASSWORD}`, compose and shell style).
static NOT_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(true|false|yes|no|on|off|null|none|[0-9]{1,6}|https?://[^:@/]+(:[0-9]+)?(/[^@]*)?|\$\{?[A-Za-z_][A-Za-z0-9_]*(:?[-?][^}]*)?\}?)$")
        .expect("NOT_SECRET is a valid regex")
});

static URL_SUFFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)_(URL|URI)$").expect("URL_SUFFIX is a valid regex"));
static URL_CREDENTIALS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"://[^/\s:@]*:[^/\s@]+@").expect("URL_CREDENTIALS is a valid regex"));

/// A variable name that holds a secret, judged by the name alone (no value to look at): `STRIPE_SECRET_KEY` yes,
/// `VERSION` or `DEVELOPER_DIR` no. A `_URL` carries a secret only with credentials in it, which a name can't show, so
/// only `DATABASE_URL` counts.
pub fn names_a_secret(name: &str) -> bool {
    let upper = name.to_uppercase();
    SECRET_NAME.is_match(&upper) && (!URL_SUFFIX.is_match(&upper) || upper.ends_with("DATABASE_URL"))
}

/// A secret-looking `NAME=value` entry: the name and the fingerprint of its value, never the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvSecret {
    pub name: String,
    pub fingerprint: String,
}

/// JS `.` does not match these; the TS pattern `^(['"])(.*)\1$` therefore refuses a quoted value spanning lines.
fn is_line_terminator(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}

/// `"value"` / `'value'` → `value` (matching quotes on one line); anything else unchanged.
fn unquote(value: &str) -> &str {
    for quote in ['"', '\''] {
        if let Some(inner) = value.strip_prefix(quote).and_then(|rest| rest.strip_suffix(quote))
            && !inner.chars().any(is_line_terminator)
        {
            return inner;
        }
    }
    value
}

/// Secret-looking `NAME=value` entries (a container's env, an env file), as
/// name + fingerprint. A `*_URL` counts only when it carries credentials.
pub fn env_secrets<S: AsRef<str>>(env: &[S]) -> Vec<EnvSecret> {
    let mut out = Vec::new();
    for entry in env {
        let entry = entry.as_ref();
        let Some(eq) = entry.find('=') else { continue };
        if eq == 0 {
            continue;
        }
        let name = js_trim(&entry[..eq]);
        let value = unquote(js_trim(&entry[eq + 1..]));
        // JS `.length` counts UTF-16 units.
        if !SECRET_NAME.is_match(&name.to_uppercase()) || value.encode_utf16().count() < 6 || NOT_SECRET.is_match(value) {
            continue;
        }
        if URL_SUFFIX.is_match(name) && !URL_CREDENTIALS.is_match(value) {
            continue;
        }
        out.push(EnvSecret { name: name.to_string(), fingerprint: fingerprint(value) });
    }
    out
}

fn gitleaks_binary() -> String {
    std::env::var("GITLEAKS_BIN").ok().filter(|b| !b.is_empty()).unwrap_or_else(|| "gitleaks".to_string())
}

/// Whether `gitleaks version` runs. Checked once per process.
static AVAILABLE: LazyLock<bool> = LazyLock::new(|| {
    let opts = RunOptions { timeout: Some(Duration::from_secs(10)), ..RunOptions::default() };
    util::run(&[gitleaks_binary(), "version".to_string()], &opts).is_ok_and(|out| out.code == Some(0))
});

pub fn gitleaks_available() -> bool {
    *AVAILABLE
}

/// What `gitleaks` may be given beyond its arguments.
#[derive(Debug, Clone, Default)]
pub struct GitleaksOptions {
    /// Piped to stdin (for `gitleaks stdin`).
    pub input: Option<String>,
    pub cwd: Option<PathBuf>,
    /// Default 10 minutes.
    pub timeout: Option<Duration>,
    /// `Some`: the child's environment is cleared, then exactly these are set. `None`: inherited.
    pub env: Option<Vec<(String, String)>>,
}

// The match is often just the token; the variable it is assigned to sits on the same input line.
static NAME_AT: LazyLock<Regex> =
    LazyLock::new(|| js_regex(r#"^\s*-?\s*(?:export\s+)?["']?([A-Za-z_][A-Za-z0-9_.-]{1,80})["']?\s*[:=]"#));

fn name_at(text: &str) -> Option<String> {
    NAME_AT.captures(text).map(|c| c[1].to_string())
}

/// Turns gitleaks' JSON report into hits with values replaced by fingerprints. `input` is the text
/// that was piped in, when any: the variable name of a hit is looked up on its line.
fn parse_report(text: &str, input: Option<&str>, command: &str) -> Result<Vec<GitleaksHit>> {
    let raw: Vec<RawHit> = match serde_json::from_str(text) {
        Ok(raw) => raw,
        Err(_) => bail!("gitleaks {command}: unreadable report"),
    };
    let lines: Option<Vec<&str>> = input.map(|i| i.split('\n').collect());
    Ok(raw
        .into_iter()
        .map(|hit| {
            let matched = hit.r#match.as_deref().unwrap_or("");
            let name = name_at(matched).or_else(|| match (hit.start_line, &lines) {
                (Some(line), Some(lines)) if line > 0 => name_at(lines.get(line as usize - 1).copied().unwrap_or("")),
                _ => None,
            });
            GitleaksHit {
                description: hit.description.clone().unwrap_or_else(|| hit.rule_id.clone()),
                file: hit.file.clone().filter(|f| !f.is_empty()),
                line: hit.start_line,
                commit: hit.commit.as_deref().filter(|c| !c.is_empty()).map(|c| c.chars().take(12).collect()),
                date: hit.date.clone().filter(|d| !d.is_empty()),
                name,
                fingerprint: fingerprint(hit.secret.as_deref().or(hit.r#match.as_deref()).unwrap_or("")),
                rule: hit.rule_id,
            }
        })
        .collect())
}

/// Runs `gitleaks <args> --report-format json --report-path -` and returns its
/// findings with values replaced by fingerprints. `options.input` is piped to stdin
/// (for `gitleaks stdin`). Gitleaks exits 1 when it finds something; that is success here.
/// A missing binary is a `GitleaksMissing` error (`err.downcast_ref::<GitleaksMissing>()`).
pub fn gitleaks(args: &[&str], options: &GitleaksOptions) -> Result<Vec<GitleaksHit>> {
    if !gitleaks_available() {
        return Err(GitleaksMissing.into());
    }
    let mut argv = vec![gitleaks_binary()];
    argv.extend(args.iter().map(|a| (*a).to_string()));
    argv.extend(["--report-format", "json", "--report-path", "-", "--no-banner", "--log-level", "error", "--exit-code", "0"].map(String::from));
    let opts = RunOptions {
        stdin: Some(options.input.clone().unwrap_or_default().into_bytes()),
        cwd: options.cwd.clone(),
        env: options.env.clone(),
        timeout: Some(options.timeout.unwrap_or(Duration::from_secs(600))),
        ..RunOptions::default()
    };
    let out = util::run(&argv, &opts)?;
    let command = args.first().copied().unwrap_or("");
    // gitleaks' stderr can quote matched lines: report only the exit, never its text.
    if out.code != Some(0) {
        match out.code {
            Some(code) => bail!("gitleaks {command} exited {code}"),
            None => bail!("gitleaks {command} exited null"),
        }
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let text = text.trim();
    if text.is_empty() {
        return Ok(Vec::new());
    }
    parse_report(text, options.input.as_deref(), command)
}

/// Scans text (an env file, a compose file, a log tail) through `gitleaks stdin`.
pub fn scan_text(text: &str) -> Result<Vec<GitleaksHit>> {
    gitleaks(&["stdin"], &GitleaksOptions { input: Some(text.to_string()), timeout: Some(Duration::from_secs(120)), ..GitleaksOptions::default() })
}

static ENV_FILE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(^|/)\.env(\.[A-Za-z0-9_-]+)?$").expect("ENV_FILE is a valid regex"));
static ENV_TEMPLATE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\.(example|sample|template|dist|defaults?)$").expect("ENV_TEMPLATE is a valid regex"));

/// Names a secret-looking file that should never be committed or world-readable.
pub fn is_env_file(path: &str) -> bool {
    ENV_FILE.is_match(path) && !ENV_TEMPLATE.is_match(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_secrets_lists_names_and_fingerprints_of_unquoted_values() {
        let env = [
            "OPENAI_API_KEY=\"sk-live-abcdef123456\"".to_string(),
            "DB_PASSWORD='hunter2hunter2'".to_string(),
            "API_TOKEN = plainvalue ".to_string(),
            "PORT=8080".to_string(),
            "APP_SECRET=${OTHER_SECRET}".to_string(),
            "SERVICE_URL=https://example.com/path".to_string(),
            "DATABASE_URL=postgres://acme:s3cretpass@db.example.com/app".to_string(),
            "TOKEN=short".to_string(),
            "=nameless-value-123".to_string(),
            "no-equals-sign".to_string(),
        ];
        let found = env_secrets(&env);
        let names: Vec<&str> = found.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["OPENAI_API_KEY", "DB_PASSWORD", "API_TOKEN", "DATABASE_URL"]);
        // The fingerprint is of the value without its quotes.
        assert_eq!(found[0].fingerprint, fingerprint("sk-live-abcdef123456"));
        assert_eq!(found[1].fingerprint, fingerprint("hunter2hunter2"));
        assert_eq!(found[2].fingerprint, fingerprint("plainvalue"));
        assert!(found.iter().all(|s| s.fingerprint.len() == 8));
    }

    #[test]
    fn gitleaks_report_keeps_fingerprints_not_values() {
        let report = r#"[{"RuleID":"generic-api-key","Description":"Generic API Key","Match":"sk-live-abcdef123456","Secret":"sk-live-abcdef123456","File":"","StartLine":2,"Commit":"0123456789abcdef0123","Date":""}]"#;
        let hits = parse_report(report, Some("# comment\nexport OPENAI_API_KEY=\"sk-live-abcdef123456\"\n"), "stdin").unwrap();
        assert_eq!(hits.len(), 1);
        let hit = &hits[0];
        assert_eq!(hit.rule, "generic-api-key");
        assert_eq!(hit.name.as_deref(), Some("OPENAI_API_KEY"));
        assert_eq!(hit.fingerprint, fingerprint("sk-live-abcdef123456"));
        assert_eq!(hit.commit.as_deref(), Some("0123456789ab"));
        assert_eq!((hit.file.as_deref(), hit.date.as_deref(), hit.line), (None, None, Some(2)));
        assert!(!format!("{hits:?}").contains("sk-live"));
        assert_eq!(parse_report("not json", None, "stdin").unwrap_err().to_string(), "gitleaks stdin: unreadable report");
    }
}
