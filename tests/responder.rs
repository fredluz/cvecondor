// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! The responder against a fake agent CLI: a `sh` script in the temp dir.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

use common::{TempDir, recorder, test_config};
use cvecondor::config::{Config, Env, Mode, build_config, process_env};
use cvecondor::notify::Notice;
use cvecondor::responder::{StartOptions, build_prompt, responder_command, responder_env, start_response, start_response_with, wait_running};
use cvecondor::state::read_state;
use cvecondor::watch::{Case, ResponseRecord, ResponseState, merge_responses};
use indexmap::IndexMap;
use serde_json::json;

fn case(key: &str, state: &str, report: &Path) -> Case {
    serde_json::from_value(json!({
        "key": key, "kind": "vulnerability", "title": key, "state": state, "reason": "high", "severity": "high", "fixAvailable": false,
        "aliases": [], "urls": [], "sources": [], "targets": [], "places": [], "report": report, "firstSeen": "", "updatedAt": ""
    }))
    .expect("the case parses")
}

fn config_in(dir: &TempDir, responder: serde_json::Value, env: &Env) -> Config {
    let raw = json!({ "stateDir": dir.path(), "collectors": [{ "type": "github", "token": "${GITHUB_TOKEN}" }], "responder": responder });
    build_config(&raw, &dir.path().join("c.json"), env).expect("the config builds")
}

#[test]
fn a_secret_the_config_references_must_be_set_and_never_reaches_logs_or_the_responder() {
    let unset = build_config(&json!({ "collectors": [{ "type": "github", "token": "${GITHUB_TOKEN}" }] }), Path::new("/x/config.json"), &Env::new());
    assert!(unset.expect_err("an unset variable is an error").to_string().contains("collectors[0].token: environment variable GITHUB_TOKEN is not set"));

    let token = "github_pat_11ABCDEFG0123456789_secretvalue";
    let dir = TempDir::new("cvecondor-responder");
    let agent = dir.path().join("fake-agent.sh");
    fs::write(
        &agent,
        format!(
            r#"dir="$CVECONDOR_WORKDIR"
if [ -n "$GITHUB_TOKEN" ]; then has=yes; else has=no; fi
printf 'Looking at left-pad in acme/api. Env has token: %s' "$has" > "$dir/outbox/01-start.md"
printf '## Message\nPinned left-pad via an override; waiting for 1.0.1.\n\n## Details\nprinted %s\n\n```cvecondor-wait\n{{"package": "npm:left-pad", "atLeast": "1.0.1"}}\n```\n' '{token}' > "$dir/report.md"
"#
        ),
    )
    .expect("writes the agent");
    let mut env = process_env();
    env.insert("GITHUB_TOKEN".into(), token.into());
    let config = config_in(&dir, json!({ "command": ["sh", agent] }), &env);
    assert!(responder_env(&config, &env, &[]).iter().all(|(name, _)| name != "GITHUB_TOKEN"), "the config's secret variables are not handed on");

    let codex = test_config(json!({ "responder": { "agent": "codex" } }));
    assert_eq!(responder_command(&codex, Mode::Propose).expect("configured")[..4], ["codex", "exec", "--sandbox", "workspace-write"]);

    let report = dir.path().join("reports").join("r.md");
    let c = case("CVE-2026-1", "pending", &report);
    let case_file = dir.path().join("case.json");
    fs::write(&case_file, "{}").expect("writes the case");
    let rec = recorder();
    start_response_with(&config, &c, &case_file, Mode::Propose, rec.notifier(), &StartOptions { env: Some(&env), ..StartOptions::default() }).expect("starts");
    wait_running();

    let notices = rec.notices();
    let first: &Notice = &notices[0];
    assert_eq!(
        (first.event.as_str(), first.title.as_str()),
        ("urgent", "Looking at left-pad in acme/api. Env has token: no"),
        "the outbox goes out as an urgent line; the token is not in the agent env"
    );
    assert_eq!(notices.last().expect("a final notice").text, "Pinned left-pad via an override; waiting for 1.0.1.");
    assert!(!fs::read_to_string(&report).expect("the report is saved").contains("secretvalue"), "the saved report is redacted");
    let mut cases = IndexMap::from([(c.key.clone(), Case { state: cvecondor::watch::CaseState::Handled, ..c.clone() })]);
    merge_responses(dir.path(), &mut cases, "");
    assert_eq!(
        serde_json::to_value(&cases[&c.key].waiting_for).expect("serializes"),
        json!([{ "kind": "package", "ecosystem": "npm", "name": "left-pad", "atLeast": "1.0.1" }])
    );
    let record: ResponseRecord = read_state(dir.path(), "responses/cve-2026-1.json").expect("the response is recorded");
    assert_eq!((record.state, record.pid), (ResponseState::Done, None));
}

#[test]
fn the_responders_triage_is_recorded_on_the_case_and_an_unknown_path_is_left_out() {
    let dir = TempDir::new("cvecondor-responder");
    let agent = dir.path().join("fake-agent.sh");
    fs::write(
        &agent,
        r#"case "$CVECONDOR_CASE" in *a.json) path=workaround;; *) path=patch-it-somehow;; esac
printf '{"path": "%s", "why": "public /preview fetches any URL; no fixed release", "rating": "act today", "fixReleased": false, "exploitable": "yes"}' "$path" > "$CVECONDOR_WORKDIR/triage.json"
printf '## Message\nact today: worked around it.\n' > "$CVECONDOR_WORKDIR/report.md"
"#,
    )
    .expect("writes the agent");
    let config = config_in(&dir, json!({ "command": ["sh", agent] }), &[("GITHUB_TOKEN".to_string(), "ghp_unused".to_string())].into());
    let mut cases = IndexMap::new();
    for key in ["a", "b"] {
        let c = case(key, "handled", &dir.path().join("reports").join(format!("{key}.md")));
        let case_file = dir.path().join(format!("{key}.json"));
        fs::write(&case_file, "{}").expect("writes the case");
        start_response(&config, &c, &case_file, Mode::Act, recorder().notifier()).expect("starts");
        cases.insert(key.to_string(), c);
    }
    wait_running();
    merge_responses(dir.path(), &mut cases, "");
    assert_eq!(
        serde_json::to_value(&cases["a"].triage).expect("serializes"),
        json!({ "path": "workaround", "why": "public /preview fetches any URL; no fixed release", "rating": "act today", "fixReleased": false, "exploitable": "yes" })
    );
    assert_eq!(cases["b"].triage, None);
}

#[test]
fn a_command_with_only_propose_runs_for_every_mode_and_its_placeholders_are_substituted() {
    let dir = TempDir::new("cvecondor-responder");
    let agent = dir.path().join("fake-agent.sh");
    fs::write(
        &agent,
        r#"out="${3#--out=}"
stdin_mode=$(grep -c '^MODE: ACT\.')
{
  echo '## Message'
  echo "mode=$2 env=$CVECONDOR_MODE"
  echo "brief_has_the_path_files=$(grep -c '^## The path files' "$1")"
  echo "report_is_in_the_workdir=$([ "$out" = "$CVECONDOR_WORKDIR/report.md" ] && echo yes || echo no)"
  echo "workdir_is_the_cwd=$([ "$(pwd -P)" = "$(cd "$4" && pwd -P)" ] && echo yes || echo no)"
  echo "prompt_on_stdin=$stdin_mode"
} > "$out"
"#,
    )
    .expect("writes the agent");
    let config = config_in(
        &dir,
        json!({ "command": { "propose": ["sh", agent, "{brief}", "{mode}", "--out={report}", "{workdir}"] } }),
        &[("GITHUB_TOKEN".to_string(), "ghp_unused".to_string())].into(),
    );
    for mode in [Mode::Propose, Mode::Update, Mode::Act] {
        assert_eq!(responder_command(&config, mode).expect("configured")[0], "sh", "the one command serves {}", mode.as_str());
    }
    let report = dir.path().join("reports").join("g.md");
    let c = case("g", "pending", &report);
    let case_file = dir.path().join("g.json");
    fs::write(&case_file, "{}").expect("writes the case");
    start_response(&config, &c, &case_file, Mode::Act, recorder().notifier()).expect("starts");
    wait_running();
    assert_eq!(
        fs::read_to_string(&report).expect("the report is saved"),
        "## Message\nmode=act env=act\nbrief_has_the_path_files=1\nreport_is_in_the_workdir=yes\nworkdir_is_the_cwd=yes\nprompt_on_stdin=1\n\n"
    );
}

#[test]
fn propose_mode_stays_shell_less_except_the_reach_the_user_commands() {
    let allowed = |reach: &[&str]| -> Vec<String> {
        let config = test_config(json!({ "responder": { "agent": "claude", "reach": reach } }));
        let argv = responder_command(&config, Mode::Propose).expect("configured");
        let at = argv.iter().position(|a| a == "--allowedTools").expect("the preset lists its tools");
        argv[at + 1].split(',').map(str::to_string).collect()
    };
    assert!(!allowed(&[]).iter().any(|t| t.starts_with("Bash")));
    assert_eq!(allowed(&["chat-send --to alice"]).into_iter().filter(|t| t.starts_with("Bash")).collect::<Vec<_>>(), ["Bash(chat-send --to alice:*)"]);

    let own = test_config(json!({ "responder": { "agent": "claude", "command": ["my-agent", "--allowedTools", "Read"], "reach": ["chat-send"] } }));
    assert_eq!(
        responder_command(&own, Mode::Propose).expect("configured"),
        ["my-agent", "--allowedTools", "Read"],
        "a user's own command is returned untouched"
    );

    let dir = TempDir::new("cvecondor-responder");
    let case_file = dir.path().join("case.json");
    fs::write(&case_file, "{}").expect("writes the case");
    let c = case("p", "pending", &dir.path().join("p.md"));
    let prompt = |reach: &[&str]| {
        let config = test_config(json!({ "responder": { "agent": "claude", "reach": reach } }));
        build_prompt(&config, &c, &case_file, Mode::Propose, dir.path(), &[]).expect("builds")
    };
    let reach_line =
        |reach: &[&str]| prompt(reach).lines().find(|l| l.starts_with("Reach-the-user commands")).expect("the prompt has the reach line").to_string();
    let none = reach_line(&[]);
    assert!(none.contains("none set up; the outbox is the only channel"), "{none}");
    assert!(none.contains("sent/NN-<stage>.md"), "even then the line is written to sent/ first: {none}");
    let two = reach_line(&["chat-send", "bridge --x"]);
    assert!(two.contains("`<command> < sent/NN-<stage>.md`"), "the commands read the sent/ copy: {two}");
    assert!(two.ends_with(": `chat-send`, `bridge --x`"), "{two}");
    for text in [none, two, prompt(&["chat-send"])] {
        assert!(!text.contains("< <that outbox file>"), "the watcher deletes outbox files within seconds, never read from there");
        assert!(!text.contains("< outbox"), "{text}");
    }
    let outbox_line = prompt(&["chat-send"]).lines().find(|l| l.starts_with("Tell the user")).expect("the prompt has the outbox line").to_string();
    let (sent_at, outbox_at) = (outbox_line.find("sent/NN-<stage>.md").expect("names sent/"), outbox_line.find("outbox/").expect("names outbox/"));
    assert!(sent_at < outbox_at, "the line is written to sent/ before it is copied to outbox/: {outbox_line}");
    assert!(outbox_line.contains("never read it back"), "{outbox_line}");
}

#[test]
fn the_work_dir_has_a_sent_dir_next_to_the_outbox_once_the_response_started() {
    let dir = TempDir::new("cvecondor-responder");
    let agent = dir.path().join("fake-agent.sh");
    fs::write(&agent, "printf '## Message\\nfine.\\n' > \"$CVECONDOR_WORKDIR/report.md\"\n").expect("writes the agent");
    let config = config_in(&dir, json!({ "command": ["sh", agent] }), &[("GITHUB_TOKEN".to_string(), "ghp_unused".to_string())].into());
    let c = case("s", "pending", &dir.path().join("reports").join("s.md"));
    let case_file = dir.path().join("s.json");
    fs::write(&case_file, "{}").expect("writes the case");
    start_response(&config, &c, &case_file, Mode::Act, recorder().notifier()).expect("starts");
    wait_running();
    let work: Vec<_> = fs::read_dir(dir.path().join("work")).expect("the work dir exists").map(|e| e.expect("entry").path()).collect();
    assert_eq!(work.len(), 1);
    for sub in ["outbox", "sent"] {
        let mode = fs::metadata(work[0].join(sub)).unwrap_or_else(|e| panic!("{sub}/ exists: {e}")).permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "{sub}/ is private");
    }
}

/// A headless agent that ends its turn while its subagents work leaves a stub, and the subagents die with it.
#[test]
fn a_run_that_ends_on_a_stub_or_an_unfinished_report_is_queued_to_retry_not_done() {
    let stub = "echo 'Two subagents are still running in the background (acme/api, acme/web). I will wait for them and write the report.'\n";
    let unfinished = "printf '## Message\\nUnfinished: acme/web is still untested.\\n' > \"$CVECONDOR_WORKDIR/report.md\"\n";
    let no_message = "printf '# Report\\nUpdating acme/api; subagents still running.\\n' > \"$CVECONDOR_WORKDIR/report.md\"\n";
    for (script, why) in [
        (stub, "ended without writing report.md: Two subagents are still running"),
        (unfinished, "its report says it is unfinished"),
        (no_message, "ended before its report was finished (report.md has no `## Message`)"),
    ] {
        let dir = TempDir::new("cvecondor-responder");
        let agent = dir.path().join("fake-agent.sh");
        fs::write(&agent, script).expect("writes the agent");
        let config = config_in(&dir, json!({ "command": ["sh", agent] }), &[("GITHUB_TOKEN".to_string(), "ghp_unused".to_string())].into());
        let c = case("u", "pending", &dir.path().join("reports").join("u.md"));
        let case_file = dir.path().join("u.json");
        fs::write(&case_file, "{}").expect("writes the case");
        let rec = recorder();
        start_response(&config, &c, &case_file, Mode::Update, rec.notifier()).expect("starts");
        wait_running();
        let record: ResponseRecord = read_state(dir.path(), "responses/u.json").expect("the response is recorded");
        assert_eq!(record.state, ResponseState::Failed, "{script}");
        assert!(record.error.as_deref().is_some_and(|e| e.starts_with(why)), "{:?} should start with {why}", record.error);
        assert!(rec.notices().iter().any(|n| n.title.starts_with("Queued to retry")), "{script}");
    }
}

#[test]
fn a_response_whose_report_is_written_and_idle_is_ended_and_recorded_as_done() {
    let dir = TempDir::new("cvecondor-responder");
    let agent = dir.path().join("fake-agent.sh");
    // The way `claude -p` can hold the run open after the report: a long wait with nothing more to do.
    let pidfile = dir.path().join("grandchild.pid");
    fs::write(
        &agent,
        format!("printf '## Message\\nact this week: updated acme-api.\\n' > \"$CVECONDOR_WORKDIR/report.md\"\nsleep 60 &\necho $! > '{}'\nwait\n", pidfile.display()),
    )
    .expect("writes the agent");
    let config = config_in(&dir, json!({ "command": ["sh", agent] }), &[("GITHUB_TOKEN".to_string(), "ghp_unused".to_string())].into());
    let report = dir.path().join("reports").join("i.md");
    let c = case("i", "pending", &report);
    let case_file = dir.path().join("i.json");
    fs::write(&case_file, "{}").expect("writes the case");
    let rec = recorder();
    let options = StartOptions { report_idle: Some(Duration::from_secs(1)), ..StartOptions::default() };
    let began = Instant::now();
    start_response_with(&config, &c, &case_file, Mode::Act, rec.notifier(), &options).expect("starts");
    wait_running();
    assert!(began.elapsed() < Duration::from_secs(30), "ended by the idle rule, not by the agent's 60 s sleep: {:?}", began.elapsed());
    // The agent's own subprocess (here a `sleep` under the `sh`) must not outlive the run.
    let grandchild: i32 = fs::read_to_string(&pidfile).expect("the agent wrote its subprocess pid").trim().parse().expect("a pid");
    let gone = (0..300).any(|_| {
        // SAFETY: signal 0 only probes whether the process exists.
        let alive = unsafe { libc::kill(grandchild, 0) } == 0;
        if alive {
            std::thread::sleep(Duration::from_millis(10));
        }
        !alive
    });
    assert!(gone, "the agent's subprocess {grandchild} is still running");

    let record: ResponseRecord = read_state(dir.path(), "responses/i.json").expect("the response is recorded");
    assert_eq!(record.state, ResponseState::Done);
    assert_eq!(record.error, None);
    assert_eq!(record.pid, None);
    assert_eq!(fs::read_to_string(&report).expect("the report is saved"), "## Message\nact this week: updated acme-api.\n\n");
    let notices: Vec<Notice> = rec.notices();
    assert_eq!(notices.len(), 1, "one result notice, no failure");
    assert!(notices[0].title.starts_with("Done: "), "{}", notices[0].title);
}

#[test]
fn a_response_that_keeps_writing_is_not_cut_off_by_the_idle_rule() {
    let dir = TempDir::new("cvecondor-responder");
    let agent = dir.path().join("fake-agent.sh");
    // Report first, then sent/ files every second for 4 s: never idle for the 3 s the rule waits.
    fs::write(
        &agent,
        "printf '## Message\\nfirst.\\n' > \"$CVECONDOR_WORKDIR/report.md\"\nmkdir -p \"$CVECONDOR_WORKDIR/sent\"\nfor n in 1 2 3 4; do sleep 1; echo x > \"$CVECONDOR_WORKDIR/sent/0$n-urgent.md\"; done\nprintf '## Message\\nlast.\\n' > \"$CVECONDOR_WORKDIR/report.md\"\n",
    )
    .expect("writes the agent");
    let config = config_in(&dir, json!({ "command": ["sh", agent] }), &[("GITHUB_TOKEN".to_string(), "ghp_unused".to_string())].into());
    let report = dir.path().join("reports").join("k.md");
    let c = case("k", "pending", &report);
    let case_file = dir.path().join("k.json");
    fs::write(&case_file, "{}").expect("writes the case");
    let options = StartOptions { report_idle: Some(Duration::from_secs(3)), ..StartOptions::default() };
    start_response_with(&config, &c, &case_file, Mode::Act, recorder().notifier(), &options).expect("starts");
    wait_running();
    let record: ResponseRecord = read_state(dir.path(), "responses/k.json").expect("the response is recorded");
    assert_eq!(record.state, ResponseState::Done);
    assert_eq!(fs::read_to_string(&report).expect("the report is saved"), "## Message\nlast.\n\n");
}

/// Runs the built binary, the way the agent in charge runs `record`.
#[test]
fn a_case_handled_in_conversation_and_recorded_is_tracked_like_a_responder_run_even_after_one_ran_the_same_day() {
    let config = test_config(json!({}));
    let state = config.dir.path();
    let config_file = state.join("config.json");
    fs::write(&config_file, json!({ "stateDir": state, "classifier": false, "collectors": [{ "type": "github", "token": "ghp_unused" }] }).to_string())
        .expect("writes the config");
    // A responder already reported on this case today, at the path a second report would also get.
    let earlier = cvecondor::watch::report_path(&config, "CVE-2026-2", cvecondor::util::now());
    let mut c = case("CVE-2026-2", "handled", &earlier);
    c.handled_by = Some(cvecondor::watch::HandledBy::Responder);
    c.severity = cvecondor::matching::Severity::Critical;
    c.aliases = vec!["GHSA-aaaa-bbbb-cccc".to_string()];
    c.handled_at = Some("2026-10-22T08:00:00.000Z".to_string());
    cvecondor::state::write_state(state, "cases.json", &IndexMap::from([(c.key.clone(), c.clone())])).expect("writes the cases");
    cvecondor::state::write_state(
        state,
        "responses/cve-2026-2.json",
        &json!({ "key": c.key, "state": "done", "startedAt": c.handled_at, "finishedAt": c.handled_at, "report": earlier }),
    )
    .expect("writes the response");
    fs::create_dir_all(earlier.parent().expect("a reports dir")).expect("creates reports/");
    fs::write(&earlier, "the responder report\n").expect("writes the earlier report");
    let mine = state.join("mine.md");
    fs::write(&mine, "## Message\nWorked around it; waiting for next 15.5.7.\n\n```cvecondor-wait\n{\"package\": \"npm:next\", \"atLeast\": \"15.5.7\"}\n```\n")
        .expect("writes my report");

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_cvecondor"))
        .args(["record", "GHSA-aaaa-bbbb-cccc", "--file"])
        .arg(&mine)
        .arg("--config")
        .arg(&config_file)
        .output()
        .expect("runs the binary");
    assert!(out.status.success(), "record exits 0: {}", String::from_utf8_lossy(&out.stderr));

    let cases: IndexMap<String, Case> = read_state(state, "cases.json").expect("the cases are saved");
    let after = &cases[&c.key];
    assert_eq!(
        serde_json::to_value(&after.waiting_for).expect("serializes"),
        json!([{ "kind": "package", "ecosystem": "npm", "name": "next", "atLeast": "15.5.7" }]),
        "the watcher now checks for the fix"
    );
    assert_eq!(after.handled_by, Some(cvecondor::watch::HandledBy::Agent));
    assert_ne!(after.report.as_deref(), Some(earlier.to_string_lossy().as_ref()));
    assert_eq!(fs::read_to_string(&earlier).expect("the earlier report stays"), "the responder report\n", "the responder's report is kept");
}

#[test]
fn a_run_that_hits_the_agents_limit_records_its_words_and_a_retry_repeats_no_urgent_line() {
    let dir = TempDir::new("cvecondor-responder");
    let agent = dir.path().join("fake-agent.sh");
    // The first run tells the user, then the agent runs out of quota (its message on stdout, exit 1). The retry says
    // the same urgent line again, then finishes.
    fs::write(
        &agent,
        r#"printf 'Working around it on api now.' > "$CVECONDOR_WORKDIR/outbox/01-urgent.md"
if [ -e "$CVECONDOR_WORKDIR/../../limit-lifted" ]; then
  printf '## Message\nact today: worked around it.\n' > "$CVECONDOR_WORKDIR/report.md"
else
  echo "You've hit your session limit · resets 7:40pm (UTC)"
  exit 1
fi
"#,
    )
    .expect("writes the agent");
    let config = config_in(&dir, json!({ "command": ["sh", agent] }), &[("GITHUB_TOKEN".to_string(), "ghp_unused".to_string())].into());
    let report = dir.path().join("reports").join("q.md");
    let c = case("q", "handled", &report);
    let case_file = dir.path().join("q.json");
    fs::write(&case_file, "{}").expect("writes the case");
    let rec = recorder();

    start_response_with(&config, &c, &case_file, Mode::Act, rec.notifier(), &StartOptions::default()).expect("starts");
    wait_running();
    let failed: ResponseRecord = read_state(dir.path(), "responses/q.json").expect("the record");
    assert_eq!(failed.state, ResponseState::Failed);
    assert_eq!(failed.error.as_deref(), Some("exit 1: You've hit your session limit · resets 7:40pm (UTC)"), "the retry queue reads the reset from this");
    assert!(rec.notices().iter().any(|n| n.title.starts_with("Queued to retry")), "a failure is queued, not 'failed'");

    fs::write(dir.path().join("limit-lifted"), "").expect("lifts the limit");
    // The work dir is named by the second.
    std::thread::sleep(Duration::from_millis(1100));
    start_response_with(&config, &c, &case_file, Mode::Act, rec.notifier(), &StartOptions { retry: true, ..StartOptions::default() }).expect("starts");
    wait_running();
    let done: ResponseRecord = read_state(dir.path(), "responses/q.json").expect("the record");
    assert_eq!((done.state, done.error), (ResponseState::Done, None));
    let urgent: Vec<String> = rec.notices().into_iter().filter(|n| n.event.as_str() == "urgent").map(|n| n.title).collect();
    assert_eq!(urgent, ["Working around it on api now."], "said once across both runs; the finished retry's own act-today line is not owed either: the user was told");
}
