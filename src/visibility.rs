// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! Whether a repo is public, read from GitHub when a responder run starts and handed to the responder in its brief.
//! What the responder writes into a repo (pull requests, branch names, commit messages, notes) must never tell the
//! public what is vulnerable, and an advisory ID in an open pull request on a public repo does exactly that, so the
//! responder needs to know. A repo whose visibility can't be read counts as public.

use serde::Deserialize;

use crate::config::{CollectorConfig, Config, GithubCollector};
use crate::http::{Fetch, Request};
use crate::name::USER_AGENT;
use crate::state::glob_match;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Public,
    Private,
}

/// One repo of a case, and what the run could learn about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoVisibility {
    pub repo: String,
    pub visibility: Visibility,
    /// Public because GitHub didn't say otherwise (no token, a failed or unreadable answer), not because it said so.
    pub assumed: bool,
}

/// GitHub's repo object: `private`, and `visibility` (`public`, `private`, `internal`).
#[derive(Deserialize)]
struct RepoObject {
    #[serde(default)]
    private: Option<bool>,
    #[serde(default)]
    visibility: Option<String>,
}

/// Private only when GitHub's answer says so (`private: true`, or a `visibility` other than `public`, which covers
/// `internal`); a public answer needs `private: false` or `visibility: public`; anything else is unknown.
fn parse(body: &[u8]) -> Option<Visibility> {
    let object: RepoObject = serde_json::from_slice(body.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(body)).ok()?;
    if object.private == Some(true) || object.visibility.as_deref().is_some_and(|v| !v.eq_ignore_ascii_case("public")) {
        return Some(Visibility::Private);
    }
    (object.private == Some(false) || object.visibility.is_some()).then_some(Visibility::Public)
}

fn is_repo_name(name: &str) -> bool {
    let part = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    name.split_once('/').is_some_and(|(owner, repo)| part(owner) && part(repo))
}

/// The GitHub collectors whose token may read `repo`: those whose repo list and exclusions include it, else all of them
/// (an explicit name outside a pattern list is still readable with the token).
fn collectors_for<'a>(config: &'a Config, repo: &str) -> Vec<&'a GithubCollector> {
    let github: Vec<&GithubCollector> = config
        .collectors
        .iter()
        .filter_map(|c| match c {
            CollectorConfig::Github(g) => Some(g),
            _ => None,
        })
        .collect();
    let covering: Vec<&GithubCollector> = github
        .iter()
        .copied()
        .filter(|g| (g.repos.is_empty() || g.repos.iter().any(|p| glob_match(p, repo))) && !g.exclude.iter().any(|p| glob_match(p, repo)))
        .collect();
    if covering.is_empty() { github } else { covering }
}

/// Reads one repo's visibility with the user's GitHub token. Unknown (no GitHub collector, a failed request, an answer
/// that says nothing) is public.
pub fn read_visibility(config: &Config, fetch: &dyn Fetch, repo: &str) -> RepoVisibility {
    let read = || -> Option<Visibility> {
        if !is_repo_name(repo) {
            return None;
        }
        collectors_for(config, repo).into_iter().find_map(|g| {
            let request = Request::get(format!("{}/repos/{repo}", g.api_url))
                .header("Authorization", format!("Bearer {}", g.token))
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .header("User-Agent", USER_AGENT);
            let response = fetch.fetch(request).ok().filter(|r| r.ok())?;
            parse(&response.body)
        })
    };
    match read() {
        Some(visibility) => RepoVisibility { repo: repo.to_string(), visibility, assumed: false },
        None => RepoVisibility { repo: repo.to_string(), visibility: Visibility::Public, assumed: true },
    }
}

/// The repos of a case: each once, in the order its places name them.
pub fn visibilities(config: &Config, fetch: &dyn Fetch, repos: &[&str]) -> Vec<RepoVisibility> {
    repos.iter().map(|repo| read_visibility(config, fetch, repo)).collect()
}

/// The section of the responder's brief that says, per repo, what it may write there. Empty when the case has no repo.
pub fn brief_section(repos: &[RepoVisibility]) -> String {
    if repos.is_empty() {
        return String::new();
    }
    let mut out = String::from(
        "\n## What you may write into each repo\n\nRead from GitHub when this run started. The rules in `common.md` (\"What you write into a repo\") apply per repo: a PUBLIC repo's pull request, branch, commits and files name no advisory ID, no exposure and nothing unpatched; a PRIVATE repo's pull request may name the advisory.\n\n",
    );
    for r in repos {
        let line = match (r.visibility, r.assumed) {
            (Visibility::Private, _) => "PRIVATE".to_string(),
            (Visibility::Public, false) => "PUBLIC".to_string(),
            (Visibility::Public, true) => "PUBLIC (its visibility could not be read: treated as public)".to_string(),
        };
        out.push_str(&format!("- {}: {line}\n", r.repo));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Response;
    use anyhow::{Result, anyhow};
    use serde_json::json;
    use std::path::Path;
    use std::sync::Mutex;

    fn config(collectors: serde_json::Value) -> Config {
        let raw = json!({ "collectors": collectors });
        crate::config::build_config(&raw, Path::new("/x/config.json"), &crate::config::Env::new()).expect("builds")
    }

    fn answer(status: u16, body: serde_json::Value) -> Result<Response> {
        Ok(Response { status, headers: Vec::new(), body: body.to_string().into_bytes() })
    }

    #[test]
    fn only_an_answer_that_says_private_makes_a_repo_private() {
        assert_eq!(parse(br#"{"private": true, "visibility": "private"}"#), Some(Visibility::Private));
        assert_eq!(parse(br#"{"visibility": "internal"}"#), Some(Visibility::Private));
        assert_eq!(parse(br#"{"private": false, "visibility": "public"}"#), Some(Visibility::Public));
        assert_eq!(parse(br#"{"private": false}"#), Some(Visibility::Public));
        assert_eq!(parse(br#"{"full_name": "acme/api"}"#), None, "an answer that doesn't say is unknown");
        assert_eq!(parse(b"<html>"), None);
    }

    #[test]
    fn unknown_visibility_counts_as_public() {
        let with_token = config(json!([{ "type": "github", "token": "t" }]));
        let say = |status: u16, body: serde_json::Value| move |_: Request| answer(status, body.clone());
        let read = |fetch: &dyn Fetch, repo: &str| read_visibility(&with_token, fetch, repo);

        let private = read(&say(200, json!({ "private": true })), "acme/api");
        assert_eq!((private.visibility, private.assumed), (Visibility::Private, false));
        let public = read(&say(200, json!({ "private": false })), "acme/api");
        assert_eq!((public.visibility, public.assumed), (Visibility::Public, false));

        for (what, got) in [
            ("an HTTP error", read(&say(404, json!({ "message": "Not Found" })), "acme/api")),
            ("a body that says nothing", read(&say(200, json!({})), "acme/api")),
            ("a transport failure", read(&|_: Request| -> Result<Response> { Err(anyhow!("connection refused")) }, "acme/api")),
            ("a name that is not owner/name", read(&say(200, json!({ "private": true })), "acme/api/../x")),
        ] {
            assert_eq!((got.visibility, got.assumed), (Visibility::Public, true), "{what} is treated as public");
        }
        let no_github = config(json!([{ "type": "host" }]));
        let asked = Mutex::new(0);
        let counting = |_: Request| -> Result<Response> {
            *asked.lock().expect("lock") += 1;
            answer(200, json!({ "private": true }))
        };
        let got = read_visibility(&no_github, &counting, "acme/api");
        assert_eq!(
            (got.visibility, got.assumed, *asked.lock().expect("lock")),
            (Visibility::Public, true, 0),
            "without a token nothing is asked and the repo is public"
        );
    }

    #[test]
    fn the_token_that_covers_the_repo_reads_it_and_a_failing_one_falls_through() {
        let config = config(json!([
            { "type": "github", "name": "work", "token": "work-token", "repos": ["acme/*"] },
            { "type": "github", "name": "me", "token": "me-token", "repos": ["me/*"] }
        ]));
        let seen = Mutex::new(Vec::new());
        let fetch = |req: Request| -> Result<Response> {
            let auth = req.headers.iter().find(|(k, _)| k == "Authorization").map(|(_, v)| v.clone()).unwrap_or_default();
            seen.lock().expect("lock").push((req.url.clone(), auth.clone()));
            if auth.contains("me-token") { answer(200, json!({ "private": true })) } else { answer(404, json!({})) }
        };
        let mine = read_visibility(&config, &fetch, "me/notes");
        assert_eq!(mine.visibility, Visibility::Private);
        assert_eq!(
            *seen.lock().expect("lock"),
            [("https://api.github.com/repos/me/notes".to_string(), "Bearer me-token".to_string())],
            "only the covering token is tried first"
        );
        let outside = read_visibility(&config, &fetch, "other/lib");
        assert_eq!(outside.visibility, Visibility::Private, "a repo no pattern covers is tried with every token");
    }

    #[test]
    fn the_brief_says_which_repos_are_public_and_calls_unknown_ones_public() {
        let section = brief_section(&[
            RepoVisibility { repo: "acme/api".into(), visibility: Visibility::Private, assumed: false },
            RepoVisibility { repo: "acme/site".into(), visibility: Visibility::Public, assumed: false },
            RepoVisibility { repo: "acme/lib".into(), visibility: Visibility::Public, assumed: true },
        ]);
        assert!(section.contains("- acme/api: PRIVATE\n"), "{section}");
        assert!(section.contains("- acme/site: PUBLIC\n"), "{section}");
        assert!(section.contains("- acme/lib: PUBLIC (its visibility could not be read: treated as public)\n"), "{section}");
        assert_eq!(brief_section(&[]), "", "a case with no repo gets no section");
    }
}
