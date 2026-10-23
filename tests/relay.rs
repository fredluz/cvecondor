// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! The Telegram reply relay: which updates reach the agent, what the agent is told, where the answer goes and that
//! the bot token never leaves the watcher.

mod common;

use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use anyhow::{Result, anyhow};
use common::TempDir;
use cvecondor::config::{Config, Env, NotifierConfig, NotifyEvent, build_config};
use cvecondor::http::{Request, Response};
use cvecondor::inbox::{keep, unread};
use cvecondor::notify::Notice;
use cvecondor::relay::{PollOptions, RelayJob, poll_once, run_job};
use cvecondor::util::{parse_time, sha256_hex};
use serde_json::{Value, json};

const TOKEN: &str = "123456:ABC-secret-bot-token";

fn now() -> jiff::Timestamp {
    parse_time("2026-10-22T08:00:00.000Z").expect("a valid time")
}

/// A config with a replying Telegram notifier whose token comes from the environment, like a real one, and a responder.
/// The bot has been read before (offset 10): a first read only skips the backlog.
fn setup(state: &Path, command: Value) -> (Config, Env) {
    let env: Env = [("BOT".to_string(), TOKEN.to_string())].into();
    let raw = json!({
        "stateDir": state,
        "collectors": [{ "type": "host" }],
        "responder": { "command": command },
        "notify": [{ "type": "telegram", "botToken": "${BOT}", "chatId": 42, "replies": true }],
    });
    let offset = state.join(format!("relay-{}.json", &sha256_hex(TOKEN.as_bytes())[..8]));
    std::fs::write(offset, r#"{ "offset": 10 }"#).expect("writes the offset");
    (build_config(&raw, &state.join("config.json"), &env).expect("builds"), env)
}

fn notifier(config: &Config) -> &NotifierConfig {
    &config.notify[0]
}

/// A Telegram double: `getUpdates` answers come from a queue, every request is kept.
struct Telegram {
    updates: Mutex<VecDeque<Value>>,
    requests: Mutex<Vec<(String, Option<Value>)>>,
}

impl Telegram {
    fn new(batches: Vec<Value>) -> Self {
        Self { updates: Mutex::new(batches.into()), requests: Mutex::new(Vec::new()) }
    }

    fn fetch(&self, req: Request) -> Result<Response> {
        let body = req.body.as_deref().map(|b| serde_json::from_slice::<Value>(b).expect("json body"));
        self.requests.lock().unwrap_or_else(PoisonError::into_inner).push((req.url.clone(), body));
        let answer = if req.url.contains("/getUpdates") {
            json!({ "ok": true, "result": self.updates.lock().unwrap_or_else(PoisonError::into_inner).pop_front().unwrap_or(json!([])) })
        } else {
            json!({ "ok": true, "result": {} })
        };
        Ok(Response { status: 200, headers: Vec::new(), body: answer.to_string().into_bytes() })
    }

    fn polls(&self) -> Vec<String> {
        self.requests.lock().unwrap_or_else(PoisonError::into_inner).iter().map(|(u, _)| u.clone()).filter(|u| u.contains("/getUpdates")).collect()
    }

    fn sent(&self) -> Vec<Value> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(u, _)| u.ends_with("/sendMessage"))
            .filter_map(|(_, b)| b.clone())
            .collect()
    }
}

fn text(update_id: i64, message_id: i64, chat: i64, text: &str) -> Value {
    json!({ "update_id": update_id, "message": { "message_id": message_id, "chat": { "id": chat }, "text": text } })
}

#[test]
fn only_texts_from_the_configured_chat_reach_the_agent_in_order_and_the_offset_persists() {
    let dir = TempDir::new("cvecondor-relay");
    let (config, env) = setup(dir.path(), json!(["agent"]));
    let telegram = Telegram::new(vec![json!([
        text(10, 1, 999, "from a stranger"),
        json!({ "update_id": 11, "message": { "message_id": 2, "chat": { "id": 42 }, "photo": [] } }),
        text(12, 5, 42, "first"),
        text(13, 6, 42, "second"),
    ])]);
    let seen = Mutex::new(Vec::<String>::new());
    let agent = |job: &RelayJob| -> Result<String> {
        seen.lock().unwrap_or_else(PoisonError::into_inner).push(job.text.clone());
        Ok(format!("answer to {}", job.text))
    };
    let logged = Mutex::new(Vec::<String>::new());
    let log = |line: &str| logged.lock().unwrap_or_else(PoisonError::into_inner).push(line.to_string());
    let options = PollOptions { env: Some(&env), log: Some(&log), ..PollOptions::default() };
    let fetch = |req: Request| telegram.fetch(req);

    let handled = poll_once(&config, notifier(&config), &fetch, &agent, &|| now(), &options).expect("polls");

    assert_eq!(handled, 2);
    assert_eq!(*seen.lock().unwrap_or_else(PoisonError::into_inner), ["first", "second"]);
    let sent = telegram.sent();
    assert_eq!(sent.len(), 2);
    assert_eq!(
        (sent[0]["chat_id"].as_str(), sent[0]["reply_to_message_id"].as_i64(), sent[0]["text"].as_str()),
        (Some("42"), Some(5), Some("answer to first"))
    );
    assert_eq!(
        (sent[1]["chat_id"].as_str(), sent[1]["reply_to_message_id"].as_i64(), sent[1]["text"].as_str()),
        (Some("42"), Some(6), Some("answer to second"))
    );
    let logged = logged.lock().unwrap_or_else(PoisonError::into_inner).join("\n");
    assert!(logged.contains("relay: ignored an update from chat 999") && logged.contains("relay: ignored an update from chat 42"), "{logged}");
    assert!(!logged.contains("stranger"), "the text of a dropped update is never logged");

    let file = dir.path().join(format!("relay-{}.json", &sha256_hex(TOKEN.as_bytes())[..8]));
    let stored: Value = serde_json::from_str(&std::fs::read_to_string(file).expect("the offset is kept")).expect("json");
    assert_eq!(stored, json!({ "offset": 14 }));
    let exchanges = unread(dir.path(), true).expect("reads the inbox");
    assert_eq!(exchanges.iter().map(|e| (e.event.as_str(), e.title.as_str())).collect::<Vec<_>>(), [("report", "reply: first"), ("report", "reply: second")]);

    // The next poll asks from the stored offset.
    let none = poll_once(&config, notifier(&config), &fetch, &agent, &|| now(), &options).expect("polls again");
    assert_eq!(none, 0);
    let polls = telegram.polls();
    assert!(polls[0].contains("&offset=10"), "{}", polls[0]);
    assert!(polls[1].contains("&offset=14"), "{}", polls[1]);
    assert!(polls[1].contains("allowed_updates=%5B%22message%22%5D"), "{}", polls[1]);
}

#[test]
fn the_prompt_has_the_last_five_urgent_lines_and_the_token_never_leaves() {
    let dir = TempDir::new("cvecondor-relay");
    let (config, mut env) = setup(dir.path(), json!(["agent"]));
    env.insert("HOME_NOTE".to_string(), "kept".to_string());
    // Seven urgent lines and one case summary in the inbox; only the last five urgent ones count.
    for n in 1..=7 {
        let at = parse_time(&format!("2026-10-22T07:0{n}:00.000Z")).expect("a valid time");
        let notice = Notice {
            event: NotifyEvent::Urgent,
            title: format!("act today: urgent line {n}"),
            text: String::new(),
            key: None,
            severity: None,
            urls: None,
            report_path: None,
        };
        keep(dir.path(), &notice, at).expect("keeps");
    }
    let case = Notice {
        event: NotifyEvent::Case,
        title: "a cycle summary".to_string(),
        text: String::new(),
        key: None,
        severity: None,
        urls: None,
        report_path: None,
    };
    keep(dir.path(), &case, parse_time("2026-10-22T07:59:00.000Z").expect("a valid time")).expect("keeps");

    let update = json!({ "update_id": 1, "message": { "message_id": 9, "chat": { "id": 42 }, "text": "yes, merge it", "reply_to_message": { "text": "fix PR waiting: acme/api#7" } } });
    let telegram = Telegram::new(vec![json!([update])]);
    let jobs = Mutex::new(Vec::<RelayJob>::new());
    let agent = |job: &RelayJob| -> Result<String> {
        jobs.lock().unwrap_or_else(PoisonError::into_inner).push(job.clone());
        Ok(format!("done, using {TOKEN}"))
    };
    let logged = Mutex::new(Vec::<String>::new());
    let log = |line: &str| logged.lock().unwrap_or_else(PoisonError::into_inner).push(line.to_string());
    // Sending fails with an error that names the token, as a careless proxy's would.
    let failing = |req: Request| -> Result<Response> {
        if req.url.ends_with("/sendMessage") { Err(anyhow!("connect {}: refused", req.url)) } else { telegram.fetch(req) }
    };
    let options = PollOptions { env: Some(&env), log: Some(&log), ..PollOptions::default() };

    poll_once(&config, notifier(&config), &failing, &agent, &|| now(), &options).expect("polls");

    let jobs = jobs.lock().unwrap_or_else(PoisonError::into_inner);
    let job = &jobs[0];
    for n in 3..=7 {
        assert!(job.prompt.contains(&format!("act today: urgent line {n}")), "line {n} is missing:\n{}", job.prompt);
    }
    assert!(!job.prompt.contains("urgent line 2") && !job.prompt.contains("a cycle summary"), "older and non-urgent entries stay out");
    assert!(job.prompt.contains("yes, merge it") && job.prompt.contains("fix PR waiting: acme/api#7"));
    assert!(job.prompt.contains("# CVECondor: you are the agent in charge"), "AGENTS.md leads the prompt");
    assert!(std::fs::read_to_string(job.workdir.join("prompt.md")).expect("prompt.md").contains("yes, merge it"));
    assert!(job.workdir.join("AGENTS.md").exists());
    assert!(!job.prompt.contains(TOKEN));
    assert!(job.env.iter().all(|(k, v)| k != "BOT" && !v.contains(TOKEN)), "the token's variable is dropped from the agent's environment");
    let has = |name: &str| job.env.iter().any(|(k, _)| k == name);
    assert!(has("CVECONDOR_CONFIG") && has("CVECONDOR_STATE_DIR") && has("CVECONDOR_WORKDIR") && has("HOME_NOTE"));

    let logged = logged.lock().unwrap_or_else(PoisonError::into_inner).join("\n");
    assert!(logged.contains("relay: could not send the reply"), "{logged}");
    assert!(!logged.contains(TOKEN), "{logged}");
    let kept = std::fs::read_to_string(&unread(dir.path(), true).expect("reads").last().expect("the exchange").file).expect("the file");
    assert!(!kept.contains(TOKEN), "the answer is redacted before it is kept");

    // A transport error out of getUpdates names the URL; the error returned has no token either.
    let broken = |req: Request| -> Result<Response> { Err(anyhow!("dial {}: refused", req.url)) };
    let err = poll_once(&config, notifier(&config), &broken, &agent, &|| now(), &options).expect_err("fails");
    assert!(!format!("{err:#}").contains(TOKEN), "{err:#}");
}

#[test]
fn a_real_agent_command_gets_the_prompt_and_its_reply_file_goes_back_clipped() {
    let dir = TempDir::new("cvecondor-relay");
    // `sh -c SCRIPT <prompt> <workdir>`: reads the prompt file, writes reply.md; the state dir comes from its environment.
    let script = r#"printf 'saw %s, state %s ' "$(grep -c 'please close it' "$0")" "$CVECONDOR_STATE_DIR" > "$1/reply.md"; head -c 2000 /dev/zero | tr '\0' x >> "$1/reply.md""#;
    let (config, mut env) = setup(dir.path(), json!(["sh", "-c", script, "{prompt}", "{workdir}"]));
    env.insert("PATH".to_string(), std::env::var("PATH").unwrap_or_default());
    let telegram = Telegram::new(vec![json!([text(1, 3, 42, "please close it")])]);
    let fetch = |req: Request| telegram.fetch(req);
    let log = |_: &str| {};
    let options = PollOptions { env: Some(&env), log: Some(&log), ..PollOptions::default() };

    let handled = poll_once(&config, notifier(&config), &fetch, &run_job, &|| now(), &options).expect("polls");

    assert_eq!(handled, 1);
    let sent = telegram.sent();
    let reply = sent[0]["text"].as_str().expect("text");
    assert!(reply.starts_with(&format!("saw 1, state {}", dir.path().display())), "{reply}");
    assert_eq!(reply.chars().count(), 1000);
    assert!(reply.ends_with('…'));
}

#[test]
fn replies_need_a_responder_and_one_reader_per_bot() {
    let dir = TempDir::new("cvecondor-relay");
    let file = dir.path().join("config.json");
    let build = |raw: Value| build_config(&raw, &file, &Env::new()).map(|_| ()).map_err(|e| e.to_string());
    let telegram = json!({ "type": "telegram", "botToken": "tok-1234", "chatId": "42", "replies": true });
    assert_eq!(
        build(json!({ "collectors": [{ "type": "host" }], "notify": [telegram] })),
        Err("notify[0].replies: needs a responder (its command runs the agent in charge)".to_string())
    );
    let responder = json!({ "command": ["agent"] });
    assert_eq!(build(json!({ "collectors": [{ "type": "host" }], "responder": responder, "notify": [telegram] })), Ok(()));
    assert_eq!(
        build(json!({ "collectors": [{ "type": "host" }], "responder": responder, "notify": [telegram, telegram] })),
        Err("notify[1].replies: another notifier already reads this bot".to_string())
    );
}

#[test]
fn the_first_read_of_a_bot_skips_its_backlog() {
    let dir = TempDir::new("cvecondor-relay");
    let (config, env) = setup(dir.path(), json!(["agent"]));
    let file = dir.path().join(format!("relay-{}.json", &sha256_hex(TOKEN.as_bytes())[..8]));
    std::fs::remove_file(&file).expect("no offset yet");
    let telegram = Telegram::new(vec![json!([text(20, 1, 42, "merge it")])]);
    let fetch = |req: Request| telegram.fetch(req);
    let agent = |_: &RelayJob| -> Result<String> { panic!("an old message must not reach the agent") };
    let options = PollOptions { env: Some(&env), ..PollOptions::default() };

    assert_eq!(poll_once(&config, notifier(&config), &fetch, &agent, &|| now(), &options).expect("polls"), 0);
    let stored: Value = serde_json::from_str(&std::fs::read_to_string(file).expect("the offset is kept")).expect("json");
    assert_eq!(stored, json!({ "offset": 21 }));
    assert!(telegram.sent().is_empty());
}

#[test]
fn a_message_the_agent_could_not_answer_is_kept_told_once_and_answered_late_after_its_reset() {
    let dir = TempDir::new("cvecondor-relay");
    let (config, env) = setup(dir.path(), json!(["agent"]));
    let telegram = Telegram::new(vec![json!([text(10, 7, 42, "yes, merge it")])]);
    let fetch = |req: Request| telegram.fetch(req);
    let log = |_: &str| {};
    let options = PollOptions { env: Some(&env), log: Some(&log), ..PollOptions::default() };
    let calls = Mutex::new(Vec::<RelayJob>::new());
    let out_of_quota = std::sync::atomic::AtomicBool::new(true);
    let agent = |job: &RelayJob| -> Result<String> {
        calls.lock().unwrap_or_else(PoisonError::into_inner).push(job.clone());
        if out_of_quota.load(std::sync::atomic::Ordering::SeqCst) {
            Err(anyhow!("exit 1: You've hit your session limit · resets 7:40pm (UTC)"))
        } else {
            Ok("merged".to_string())
        }
    };
    let at = |time: &str| {
        let t = parse_time(time).expect("a valid time");
        move || t
    };

    let handled = poll_once(&config, notifier(&config), &fetch, &agent, &at("2026-10-22T08:00:00Z"), &options).expect("polls");
    assert_eq!(handled, 0);
    let sent = telegram.sent();
    assert_eq!(sent.len(), 1, "told once that it is kept");
    let told = sent[0]["text"].as_str().expect("text");
    assert!(told.contains("I can't answer right now") && told.contains("resets 7:40pm (UTC)") && told.contains("2026-10-22T19:41:00.000Z"), "{told}");

    poll_once(&config, notifier(&config), &fetch, &agent, &at("2026-10-22T12:00:00Z"), &options).expect("polls");
    assert_eq!(calls.lock().unwrap_or_else(PoisonError::into_inner).len(), 1, "the agent is not asked again before its reset");

    out_of_quota.store(false, std::sync::atomic::Ordering::SeqCst);
    let handled = poll_once(&config, notifier(&config), &fetch, &agent, &at("2026-10-22T19:45:00Z"), &options).expect("polls");
    assert_eq!(handled, 1);
    let sent = telegram.sent();
    assert_eq!((sent.len(), sent[1]["text"].as_str(), sent[1]["reply_to_message_id"].as_i64()), (2, Some("merged"), Some(7)), "the late answer points at the original message");
    let calls = calls.lock().unwrap_or_else(PoisonError::into_inner);
    assert!(calls[1].prompt.contains("Answered late") && calls[1].prompt.contains("yes, merge it") && !calls[0].prompt.contains("Answered late"));
    let again = poll_once(&config, notifier(&config), &fetch, &agent, &at("2026-10-22T23:00:00Z"), &options).expect("polls");
    assert_eq!((again, calls.len()), (0, 2), "answered once, not again");
}
