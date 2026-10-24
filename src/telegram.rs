// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! `cvecondor telegram-chat`: finds the chat id of the person who wrote to CVECondor's bot, and writes it into the
//! config. The token comes from the env file (never printed, never on a command line), the chat from what Telegram
//! holds for the bot (`getUpdates` without an offset, which confirms nothing, so the relay's first read still sees
//! everything) plus the chats the relay has seen. While the watcher's relay holds the bot, Telegram answers a second
//! reader with 409: the command then reads only what the relay recorded, so it is safe to run at any time.

use std::fs;
use std::ops::Range;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;

use crate::config::{Config, Env, build_config, config_path, load_config, load_env_file, parse_jsonc, process_env};
use crate::http::{Fetch, Request};
use crate::name::{NAME, USER_AGENT};
use crate::relay::{Chat, chat_of, seen_chats};

const API: &str = "https://api.telegram.org";
/// The variable the setup guide puts the token in.
const DEFAULT_TOKEN_VAR: &str = "TELEGRAM_BOT_TOKEN";
/// One getUpdates long poll while `--wait` waits for the user to tap Start.
const WAIT_STEP: u64 = 25;

/// What the command line asked for.
#[derive(Default)]
pub struct Options<'a> {
    pub config: Option<&'a str>,
    /// The env variable holding the token; default: the config's only Telegram notifier's, else `TELEGRAM_BOT_TOKEN`.
    pub token_var: Option<&'a str>,
    /// Seconds to wait for a chat to appear.
    pub wait: u64,
    /// A chat id from the list, or `only`: write it into the config.
    pub use_chat: Option<&'a str>,
    /// With `use_chat`: also turn `replies` on.
    pub replies: bool,
}

// ---------- reading and writing JSONC in place (comments and layout stay) ----------

/// The index after whitespace and comments.
fn trivia(t: &[u8], mut i: usize) -> usize {
    loop {
        match t.get(i) {
            Some(b' ' | b'\t' | b'\r' | b'\n') => i += 1,
            Some(b'/') if t.get(i + 1) == Some(&b'/') => {
                while i < t.len() && t[i] != b'\n' {
                    i += 1;
                }
            }
            Some(b'/') if t.get(i + 1) == Some(&b'*') => {
                i = t[i + 2..].windows(2).position(|w| w == b"*/").map_or(t.len(), |p| i + 2 + p + 2);
            }
            _ => return i,
        }
    }
}

/// The end of the string that starts at `i`.
fn string_end(t: &[u8], i: usize) -> Result<usize> {
    let mut j = i + 1;
    loop {
        match t.get(j) {
            None => bail!("config: a string is not closed"),
            Some(b'\\') => j += 2,
            Some(b'"') => return Ok(j + 1),
            Some(_) => j += 1,
        }
    }
}

/// The end of the value that starts at `i`.
fn value_end(t: &[u8], i: usize) -> Result<usize> {
    match t.get(i) {
        None => bail!("config: a value is missing"),
        Some(b'"') => string_end(t, i),
        Some(b'{') => Ok(entries(t, i, b'}')?.1),
        Some(b'[') => Ok(entries(t, i, b']')?.1),
        Some(_) => {
            let mut j = i;
            while j < t.len() && !matches!(t[j], b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n' | b'/') {
                j += 1;
            }
            if j == i { bail!("config: unexpected character at byte {i}") } else { Ok(j) }
        }
    }
}

/// A member (key and value span) or an array item (no key).
type Entry = (Option<String>, Range<usize>);

/// The members of the object (keys with value spans) or items of the array that opens at `start`, and where it ends.
fn entries(t: &[u8], start: usize, close: u8) -> Result<(Vec<Entry>, usize)> {
    let mut out = Vec::new();
    let mut i = start + 1;
    loop {
        i = trivia(t, i);
        match t.get(i) {
            None => bail!("config: not closed"),
            Some(c) if *c == close => return Ok((out, i + 1)),
            Some(_) => {}
        }
        let key = if close == b'}' {
            if t[i] != b'"' {
                bail!("config: expected a key at byte {i}");
            }
            let end = string_end(t, i)?;
            let key = String::from_utf8_lossy(&t[i + 1..end - 1]).into_owned();
            i = trivia(t, end);
            if t.get(i) != Some(&b':') {
                bail!("config: expected ':' at byte {i}");
            }
            i = trivia(t, i + 1);
            Some(key)
        } else {
            None
        };
        let end = value_end(t, i)?;
        out.push((key, i..end));
        i = trivia(t, end);
        match t.get(i) {
            Some(b',') => i += 1,
            Some(c) if *c == close => {}
            _ => bail!("config: expected ',' at byte {i}"),
        }
    }
}

fn member(members: &[(Option<String>, Range<usize>)], key: &str) -> Option<Range<usize>> {
    members.iter().find(|(k, _)| k.as_deref() == Some(key)).map(|(_, span)| span.clone())
}

/// `text` with the chat id set on the Telegram notifier that reads `${var}`, and `replies` on when asked. A notifier
/// for that bot is added when there is none. Everything else, comments included, stays as it was.
pub fn set_chat(text: &str, var: &str, chat_id: &str, replies: bool) -> Result<String> {
    let t = text.as_bytes();
    let top = trivia(t, 0);
    if t.get(top) != Some(&b'{') {
        bail!("config: expected a JSON object");
    }
    let (members, _) = entries(t, top, b'}')?;
    let reference = format!("\"${{{var}}}\"");
    let new_item =
        format!("{{ \"type\": \"telegram\", \"botToken\": {reference}, \"chatId\": \"{chat_id}\"{} }}", if replies { ", \"replies\": true" } else { "" });
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    match member(&members, "notify") {
        None => edits.push((top + 1, top + 1, format!("\n  \"notify\": [\n    {new_item}\n  ],"))),
        Some(list) => {
            if t[list.start] != b'[' {
                bail!("config: notify is not a list");
            }
            let (items, _) = entries(t, list.start, b']')?;
            let mut mine = Vec::new();
            let mut other_telegram = 0;
            for (_, span) in &items {
                if t[span.start] != b'{' {
                    continue;
                }
                let (ms, _) = entries(t, span.start, b'}')?;
                if member(&ms, "type").is_some_and(|s| &text[s] == "\"telegram\"") {
                    if member(&ms, "botToken").is_some_and(|s| text[s] == reference) {
                        mine.push(ms);
                    } else {
                        other_telegram += 1;
                    }
                }
            }
            match mine.as_slice() {
                [] if other_telegram > 0 => {
                    bail!("the config has a telegram notifier that does not read ${{{var}}}: name its variable with --env")
                }
                [] => match items.last() {
                    Some((_, last)) => edits.push((last.end, last.end, format!(",\n    {new_item}"))),
                    None => edits.push((list.start + 1, list.start + 1, format!("\n    {new_item}\n  "))),
                },
                [ms] => {
                    let token = member(ms, "botToken").expect("matched on it");
                    let mut after = match member(ms, "chatId") {
                        Some(span) => {
                            edits.push((span.start, span.end, format!("\"{chat_id}\"")));
                            None
                        }
                        None => Some((token.end, format!(", \"chatId\": \"{chat_id}\""))),
                    };
                    if replies {
                        match member(ms, "replies") {
                            Some(span) => edits.push((span.start, span.end, "true".to_string())),
                            None => match after.as_mut() {
                                Some((_, extra)) => extra.push_str(", \"replies\": true"),
                                None => {
                                    let at = member(ms, "chatId").expect("present").end;
                                    edits.push((at, at, ", \"replies\": true".to_string()));
                                }
                            },
                        }
                    }
                    if let Some((at, extra)) = after {
                        edits.push((at, at, extra));
                    }
                }
                _ => bail!("the config has several telegram notifiers that read ${{{var}}}: edit chatId by hand"),
            }
        }
    }
    edits.sort_by_key(|e| std::cmp::Reverse(e.0));
    let mut out = text.to_string();
    for (from, to, with) in edits {
        out.replace_range(from..to, &with);
    }
    Ok(out)
}

/// The variable the config's only Telegram notifier reads its token from, if it reads one.
fn configured_token_var(raw: &Value) -> Option<String> {
    let telegram: Vec<&Value> = raw.get("notify")?.as_array()?.iter().filter(|n| n.get("type").and_then(Value::as_str) == Some("telegram")).collect();
    let [only] = telegram.as_slice() else { return None };
    let token = only.get("botToken")?.as_str()?;
    token.strip_prefix("${")?.strip_suffix('}').map(str::to_string)
}

// ---------- talking to Telegram ----------

fn get(fetch: &dyn Fetch, token: &str, method: &str, query: &str, wait: u64) -> Result<(u16, Value)> {
    let request = Request::get(format!("{API}/bot{token}/{method}{query}")).header("user-agent", USER_AGENT).timeout(Duration::from_secs(wait + 20));
    // A transport error can name the URL, so the token never goes out in it.
    let res = fetch.fetch(request).map_err(|e| anyhow!("{}", format!("{e:#}").replace(token, "[token]")))?;
    let body = res.json::<Value>().unwrap_or(Value::Null);
    Ok((res.status, body))
}

fn description(body: &Value) -> &str {
    body.get("description").and_then(Value::as_str).unwrap_or("no description")
}

/// Telegram's name for the bot: `getMe`. Fails in plain words when the token is not one.
fn bot_username(fetch: &dyn Fetch, token: &str, var: &str) -> Result<String> {
    let (status, body) = get(fetch, token, "getMe", "", 0)?;
    if status == 401 || status == 404 {
        bail!("Telegram does not know the token in {var} (HTTP {status}): it was pasted wrong or revoked; put a fresh one in the env file");
    }
    if !(200..300).contains(&status) || body.get("ok") != Some(&Value::Bool(true)) {
        bail!("getMe: HTTP {status}: {}", description(&body));
    }
    body.pointer("/result/username").and_then(Value::as_str).map(str::to_string).ok_or_else(|| anyhow!("getMe: no username in the answer"))
}

/// What Telegram holds for the bot, read without confirming anything. `None`: another reader holds the bot.
fn waiting_chats(fetch: &dyn Fetch, token: &str, wait: u64) -> Result<Option<Vec<Chat>>> {
    let (status, body) = get(fetch, token, "getUpdates", &format!("?timeout={wait}"), wait)?;
    if status == 409 {
        if description(&body).to_lowercase().contains("webhook") {
            bail!("a webhook is set on this bot, so getUpdates is off: it is not a bot for CVECondor; make a new one in @BotFather");
        }
        return Ok(None);
    }
    if !(200..300).contains(&status) || body.get("ok") != Some(&Value::Bool(true)) {
        bail!("getUpdates: HTTP {status}: {}", description(&body));
    }
    Ok(Some(body.get("result").and_then(Value::as_array).map(|u| u.iter().filter_map(chat_of).collect()).unwrap_or_default()))
}

fn merge(into: &mut Vec<Chat>, more: Vec<Chat>) {
    for chat in more {
        match into.iter_mut().find(|c| c.id == chat.id) {
            Some(known) => *known = chat,
            None => into.push(chat),
        }
    }
}

/// The whole command. Returns what to print.
pub fn run(opts: &Options, fetch: &dyn Fetch) -> Result<String> {
    let mut env: Env = process_env();
    let file = config_path(opts.config, &env);
    for (name, value) in load_env_file(&file)? {
        // The last line for a name wins, and a variable already set wins over the file (as for the watcher).
        if std::env::var_os(&name).is_none() {
            env.insert(name, value);
        }
    }
    let config_text = fs::read_to_string(&file).ok();
    let raw = config_text.as_deref().and_then(|t| parse_jsonc(t).ok());
    let var = opts.token_var.map(str::to_string).or_else(|| raw.as_ref().and_then(configured_token_var)).unwrap_or_else(|| DEFAULT_TOKEN_VAR.to_string());
    let token = env
        .get(&var)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| anyhow!("{var} is not set: put it in {} (the setup guide, docs/telegram.md, step 3)", file.with_file_name("cvecondor.env").display()))?
        .clone();

    let username = bot_username(fetch, &token, &var)?;
    let link = format!("https://t.me/{username}");
    let loaded: Option<Config> = load_config(opts.config, &process_env()).ok();

    // Direct read, then the relay's record. With `--wait`, look again until someone has written or the time is up.
    let deadline = Instant::now() + Duration::from_secs(opts.wait);
    let mut chats: Vec<Chat> = Vec::new();
    let mut shared = false;
    loop {
        if let Some(config) = &loaded {
            merge(&mut chats, seen_chats(&config.state_dir, &token));
        }
        let left = deadline.saturating_duration_since(Instant::now()).as_secs();
        match waiting_chats(fetch, &token, left.min(WAIT_STEP))? {
            Some(direct) => merge(&mut chats, direct),
            None => {
                shared = true;
                if left > 0 && chats.is_empty() {
                    std::thread::sleep(Duration::from_secs(2.min(left)));
                }
            }
        }
        if !chats.is_empty() || Instant::now() >= deadline {
            break;
        }
    }

    let mut out = vec![format!("Bot: @{username} ({link})")];
    if shared {
        out.push("The watcher is reading this bot, so these are the chats it has seen.".to_string());
    }
    if chats.is_empty() {
        out.push(format!("No chat has written to @{username} yet. Open {link}, tap Start, then run this again (--wait 120 waits for it)."));
        if opts.use_chat.is_some() {
            bail!("{}", out.join("\n"));
        }
        return Ok(out.join("\n"));
    }
    out.push("Chats that wrote to it:".to_string());
    out.extend(chats.iter().map(|c| format!("  {}  {}", c.id, c.describe())));

    let Some(choice) = opts.use_chat else {
        out.push(format!("Write one into the config: {NAME} telegram-chat --use <id>{}", if opts.replies { " --replies" } else { "" }));
        return Ok(out.join("\n"));
    };
    let chat = if choice == "only" {
        match chats.as_slice() {
            [only] => only,
            _ => bail!("{}\nmore than one chat wrote to the bot: pick one with --use <id>", out.join("\n")),
        }
    } else {
        let id: i64 = choice.parse().with_context(|| format!("--use takes a chat id from the list or 'only', not '{choice}'"))?;
        chats.iter().find(|c| c.id == id).ok_or_else(|| anyhow!("{}\nchat {id} has not written to this bot: pick one of the list", out.join("\n")))?
    };
    let text = config_text.ok_or_else(|| anyhow!("no config at {}: create it first (examples/config.example.jsonc)", file.display()))?;
    let changed = set_chat(&text, &var, &chat.id.to_string(), opts.replies)?;
    // Whatever worked before must still load; a config that was already broken is the user's to fix.
    let was_fine = parse_jsonc(&text).ok().is_some_and(|r| build_config(&r, &file, &env).is_ok());
    if was_fine {
        let new = parse_jsonc(&changed).and_then(|r| build_config(&r, &file, &env));
        if let Err(e) = new {
            bail!("the change would make the config invalid, so nothing was written: {e:#}");
        }
    }
    fs::write(&file, changed).with_context(|| format!("write {}", file.display()))?;
    out.push(format!(
        "Wrote chatId {} into the telegram notifier in {}{}. Restart the watcher to read it, then `{NAME} status`.",
        chat.id,
        file.display(),
        if opts.replies { " and turned replies on" } else { "" }
    ));
    Ok(out.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"{
  // where urgent things reach you
  "collectors": [{ "type": "github", "token": "${GITHUB_TOKEN}" }],
  "notify": [
    { "type": "telegram", "botToken": "${TELEGRAM_BOT_TOKEN}", "chatId": "123456789" }   // setup: docs/telegram.md
    // { "type": "slack", "webhookUrl": "${SLACK_WEBHOOK_URL}" },
  ]
}
"#;

    #[test]
    fn the_chat_id_is_replaced_in_place_and_comments_stay() {
        let out = set_chat(EXAMPLE, "TELEGRAM_BOT_TOKEN", "-1001", true).expect("edits");
        assert!(out.contains(r#""chatId": "-1001", "replies": true }   // setup: docs/telegram.md"#), "{out}");
        assert!(out.contains("// where urgent things reach you") && out.contains("// { \"type\": \"slack\""), "{out}");
        let value = parse_jsonc(&out).expect("still valid");
        assert_eq!(value["notify"][0]["chatId"], "-1001");
        assert_eq!(value["notify"][0]["replies"], true);
    }

    #[test]
    fn a_notifier_without_a_chat_gets_one_and_replies_already_there_are_switched_on() {
        let text = r#"{ "notify": [{ "type": "telegram", "botToken": "${BOT}", "replies": false }] }"#;
        let out = set_chat(text, "BOT", "42", true).expect("edits");
        let value = parse_jsonc(&out).expect("valid");
        assert_eq!(value["notify"][0], serde_json::json!({ "type": "telegram", "botToken": "${BOT}", "chatId": "42", "replies": true }));
        // Without --replies it is left as it was.
        let out = set_chat(text, "BOT", "42", false).expect("edits");
        assert_eq!(parse_jsonc(&out).expect("valid")["notify"][0]["replies"], false);
    }

    #[test]
    fn a_notifier_is_added_to_a_list_that_has_none_or_none_at_all() {
        let other = r#"{ "notify": [{ "type": "slack", "webhookUrl": "${S}" }] }"#;
        let value = parse_jsonc(&set_chat(other, "TELEGRAM_BOT_TOKEN", "7", false).expect("edits")).expect("valid");
        assert_eq!(value["notify"].as_array().map(Vec::len), Some(2));
        assert_eq!(value["notify"][1]["chatId"], "7");
        for text in [r#"{ "notify": [] }"#, r#"{ "collectors": [] }"#, "{}"] {
            let value = parse_jsonc(&set_chat(text, "TELEGRAM_BOT_TOKEN", "7", true).expect("edits")).expect("valid");
            assert_eq!(value["notify"][0]["botToken"], "${TELEGRAM_BOT_TOKEN}", "{text}");
            assert_eq!(value["notify"][0]["replies"], true, "{text}");
        }
    }

    #[test]
    fn a_telegram_notifier_on_another_variable_is_never_duplicated() {
        let text = r#"{ "notify": [{ "type": "telegram", "botToken": "${OTHER}", "chatId": "1" }] }"#;
        assert!(set_chat(text, "TELEGRAM_BOT_TOKEN", "7", false).is_err());
        assert_eq!(configured_token_var(&parse_jsonc(text).expect("valid")).as_deref(), Some("OTHER"));
    }

    #[test]
    fn strings_that_look_like_structure_do_not_confuse_the_scanner() {
        let text = r#"{ "notes": "a } ] , \" // not a comment", /* c */ "notify": [{ "type": "telegram", "botToken": "${B}", "chatId": 5 }] }"#;
        let value = parse_jsonc(&set_chat(text, "B", "9", false).expect("edits")).expect("valid");
        assert_eq!(value["notify"][0]["chatId"], "9");
        assert_eq!(value["notes"], "a } ] , \" // not a comment");
    }
}
