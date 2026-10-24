// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! `cvecondor telegram-chat`: the token comes from the env file and never shows, the chat is found without
//! confirming any update, and the config is edited in place or left alone.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use anyhow::{Result, anyhow};
use common::TempDir;
use cvecondor::config::{Env, build_config, parse_jsonc};
use cvecondor::http::{Request, Response};
use cvecondor::relay::{PollOptions, RelayJob, poll_once};
use cvecondor::telegram::{Options, run};
use cvecondor::util::parse_time;
use serde_json::{Value, json};

const TOKEN: &str = "555000:ZZ-secret-token-of-the-test";
const VAR: &str = "TG_CHAT_TEST_BOT";

fn answer(status: u16, body: Value) -> Result<Response> {
    Ok(Response { status, headers: Vec::new(), body: body.to_string().into_bytes() })
}

/// A config dir with an env file holding the token, and a config (text given) that references it.
fn setup(config: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new("cvecondor-telegram");
    std::fs::write(dir.path().join("cvecondor.env"), format!("OTHER=1\n{VAR}={TOKEN}\n")).expect("writes the env file");
    let file = dir.path().join("config.json");
    std::fs::write(&file, config.replace("STATE", &dir.path().join("state").to_string_lossy())).expect("writes the config");
    (dir, file)
}

const CONFIG: &str = r#"{
  // where it runs
  "stateDir": "STATE",
  "collectors": [{ "type": "host" }],
  "responder": { "command": ["agent"] },
  "notify": [
    { "type": "telegram", "botToken": "${TG_CHAT_TEST_BOT}", "chatId": "1" }   // my phone
  ]
}
"#;

fn private(id: i64, name: &str) -> Value {
    json!({ "update_id": id, "message": { "message_id": 1, "text": "/start", "chat": { "id": id * 1000, "type": "private", "first_name": name } } })
}

/// Telegram's side: `getMe`, and `getUpdates` as given. Every URL is kept.
struct Bot {
    updates: Value,
    updates_status: u16,
    urls: Mutex<Vec<String>>,
}

impl Bot {
    fn with(updates: Vec<Value>) -> Self {
        Self { updates: json!(updates), updates_status: 200, urls: Mutex::new(Vec::new()) }
    }

    fn fetch(&self, req: Request) -> Result<Response> {
        self.urls.lock().unwrap_or_else(PoisonError::into_inner).push(req.url.clone());
        if !req.url.contains(TOKEN) {
            return answer(401, json!({ "ok": false, "error_code": 401, "description": "Unauthorized" }));
        }
        if req.url.contains("/getMe") {
            return answer(200, json!({ "ok": true, "result": { "username": "acme_cvecondor_bot" } }));
        }
        match self.updates_status {
            200 => answer(200, json!({ "ok": true, "result": self.updates })),
            status => answer(status, self.updates.clone()),
        }
    }
}

fn options<'a>(file: &'a Path) -> Options<'a> {
    Options { config: file.to_str(), token_var: Some(VAR), ..Options::default() }
}

#[test]
fn it_lists_the_chats_with_the_bot_and_confirms_nothing_so_the_relay_still_sees_the_backlog() {
    let (_dir, file) = setup(CONFIG);
    let bot = Bot::with(vec![
        private(7, "Ana"),
        private(7, "Ana"),
        json!({ "update_id": 9, "my_chat_member": { "chat": { "id": -100777, "type": "supergroup", "title": "Ops" } } }),
    ]);
    let out = run(&options(&file), &|req: Request| bot.fetch(req)).expect("runs");

    assert_eq!(
        out,
        "Bot: @acme_cvecondor_bot (https://t.me/acme_cvecondor_bot)\nChats that wrote to it:\n  7000  private: Ana\n  -100777  supergroup: \"Ops\"\n\
         Write one into the config: cvecondor telegram-chat --use <id>"
    );
    assert!(!out.contains(TOKEN));
    let urls = bot.urls.lock().unwrap_or_else(PoisonError::into_inner);
    assert!(urls.iter().all(|u| !u.contains("offset")), "reading must not confirm updates: {urls:?}");
    assert_eq!(std::fs::read_to_string(&file).expect("reads").matches("\"1\"").count(), 1, "listing changes nothing");
}

#[test]
fn use_writes_the_chat_id_in_place_keeping_comments_and_turns_replies_on() {
    let (_dir, file) = setup(CONFIG);
    let bot = Bot::with(vec![private(7, "Ana")]);
    let out = run(&Options { use_chat: Some("only"), replies: true, ..options(&file) }, &|req: Request| bot.fetch(req)).expect("runs");
    assert!(out.contains("Wrote chatId 7000 into the telegram notifier") && out.contains("turned replies on"), "{out}");

    let written = std::fs::read_to_string(&file).expect("reads");
    assert!(written.contains("// where it runs") && written.contains("// my phone"), "{written}");
    let value = parse_jsonc(&written).expect("still valid");
    assert_eq!(value["notify"][0]["chatId"], "7000");
    assert_eq!(value["notify"][0]["replies"], true);
    let env: Env = [(VAR.to_string(), TOKEN.to_string())].into();
    build_config(&value, &file, &env).expect("the written config loads");
}

#[test]
fn use_needs_a_chat_from_the_list_and_only_when_there_is_exactly_one() {
    let (_dir, file) = setup(CONFIG);
    let bot = Bot::with(vec![private(7, "Ana"), private(8, "Bo")]);
    let fetch = |req: Request| bot.fetch(req);
    let err = run(&Options { use_chat: Some("only"), ..options(&file) }, &fetch).expect_err("two chats").to_string();
    assert!(err.contains("more than one chat wrote to the bot: pick one with --use <id>") && err.contains("7000") && err.contains("8000"), "{err}");
    let err = run(&Options { use_chat: Some("12345"), ..options(&file) }, &fetch).expect_err("not in the list").to_string();
    assert!(err.contains("chat 12345 has not written to this bot"), "{err}");
    assert_eq!(std::fs::read_to_string(&file).expect("reads"), CONFIG.replace("STATE", &file.parent().expect("dir").join("state").to_string_lossy()));

    run(&Options { use_chat: Some("8000"), ..options(&file) }, &fetch).expect("picks one");
    assert_eq!(parse_jsonc(&std::fs::read_to_string(&file).expect("reads")).expect("valid")["notify"][0]["chatId"], "8000");
}

#[test]
fn a_change_that_would_break_a_working_config_is_not_written() {
    // Replies need a responder: without one the edited config would not load.
    let (_dir, file) = setup(&CONFIG.replace("  \"responder\": { \"command\": [\"agent\"] },\n", ""));
    let before = std::fs::read_to_string(&file).expect("reads");
    let bot = Bot::with(vec![private(7, "Ana")]);
    let err = run(&Options { use_chat: Some("only"), replies: true, ..options(&file) }, &|req: Request| bot.fetch(req)).expect_err("refused").to_string();
    assert!(err.contains("nothing was written") && err.contains("needs a responder"), "{err}");
    assert_eq!(std::fs::read_to_string(&file).expect("reads"), before);
}

#[test]
fn while_the_relay_holds_the_bot_it_reads_what_the_relay_saw_instead_of_fighting_it() {
    let (dir, file) = setup(CONFIG);
    // The watcher's relay reads the bot first (its first read skips the backlog but remembers who wrote).
    let env: Env = [(VAR.to_string(), TOKEN.to_string())].into();
    let raw = parse_jsonc(&std::fs::read_to_string(&file).expect("reads")).expect("valid");
    let mut raw = raw;
    raw["notify"][0]["replies"] = json!(true);
    let config = build_config(&raw, &file, &env).expect("builds");
    let bot = Bot::with(vec![private(7, "Ana")]);
    let agent = |_: &RelayJob| -> Result<String> { Err(anyhow!("no agent in this test")) };
    let at = parse_time("2026-10-22T08:00:00.000Z").expect("a time");
    poll_once(&config, &config.notify[0], &|req: Request| bot.fetch(req), &agent, &|| at, &PollOptions { env: Some(&env), ..PollOptions::default() })
        .expect("the relay's first read");

    // Now Telegram answers a second reader with 409.
    let held =
        Bot { updates: json!({ "ok": false, "description": "Conflict: terminated by other getUpdates request" }), updates_status: 409, ..Bot::with(vec![]) };
    let out = run(&options(&file), &|req: Request| held.fetch(req)).expect("runs anyway");
    assert!(out.contains("The watcher is reading this bot, so these are the chats it has seen.\nChats that wrote to it:\n  7000  private: Ana"), "{out}");
    assert!(dir.path().join("state").is_dir());
}

#[test]
fn a_webhook_a_wrong_token_and_a_missing_token_are_said_in_plain_words_without_the_token() {
    let (_dir, file) = setup(CONFIG);
    let webhook = Bot {
        updates: json!({ "ok": false, "description": "Conflict: can't use getUpdates method while webhook is active" }),
        updates_status: 409,
        ..Bot::with(vec![])
    };
    let err = run(&options(&file), &|req: Request| webhook.fetch(req)).expect_err("a webhook").to_string();
    assert!(err.starts_with("a webhook is set on this bot"), "{err}");

    let revoked = |_: Request| answer(401, json!({ "ok": false }));
    let err = run(&options(&file), &revoked).expect_err("a wrong token").to_string();
    assert!(err.starts_with(&format!("Telegram does not know the token in {VAR} (HTTP 401)")) && !err.contains(TOKEN), "{err}");

    let failing = |req: Request| Err::<Response, _>(anyhow!("connect failed for {}", req.url));
    let err = format!("{:#}", run(&options(&file), &failing).expect_err("no network"));
    assert!(err.contains("connect failed") && !err.contains(TOKEN), "{err}");

    let err = run(&Options { token_var: Some("TG_CHAT_TEST_MISSING"), ..options(&file) }, &revoked).expect_err("no variable").to_string();
    assert!(err.starts_with("TG_CHAT_TEST_MISSING is not set: put it in "), "{err}");
}

#[test]
fn with_nobody_having_written_it_says_what_to_do() {
    let (_dir, file) = setup(CONFIG);
    let bot = Bot::with(vec![]);
    let out = run(&options(&file), &|req: Request| bot.fetch(req)).expect("runs");
    assert_eq!(
        out,
        "Bot: @acme_cvecondor_bot (https://t.me/acme_cvecondor_bot)\nNo chat has written to @acme_cvecondor_bot yet. Open https://t.me/acme_cvecondor_bot, tap Start, then run this again (--wait 120 waits for it)."
    );
    assert!(run(&Options { use_chat: Some("only"), ..options(&file) }, &|req: Request| bot.fetch(req)).is_err());
}
