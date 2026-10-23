// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! Notifier delivery: the SMTP client against a fake server, the events filter,
//! and that a failing notifier's error never carries its token or webhook URL.

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};

use anyhow::{Result, anyhow};
use common::test_config;
use cvecondor::config::NotifyEvent;
use cvecondor::http::{Request, Response};
use cvecondor::notify::{Notice, SendResult, send_notice};
use cvecondor::util::{base64_decode, parse_time};
use serde_json::{Value, json};

fn notice() -> Notice {
    Notice {
        event: NotifyEvent::Case,
        title: "[cvecondor] crítico: CVE-2026-1234 em acme/api — ação necessária já".to_string(),
        text: "lodash 4.17.20\nupgrade to 4.17.21 — ok?\n".repeat(5),
        key: None,
        severity: None,
        urls: None,
        report_path: None,
    }
}

fn now() -> jiff::Timestamp {
    parse_time("2026-10-21T06:00:00.000Z").expect("a valid time")
}

fn ok(body: &str) -> Result<Response> {
    Ok(Response { status: 200, headers: Vec::new(), body: body.as_bytes().to_vec() })
}

fn status(status: u16, body: &str) -> Result<Response> {
    Ok(Response { status, headers: Vec::new(), body: body.as_bytes().to_vec() })
}

/// What the fake relay saw: the decoded AUTH PLAIN credentials and the DATA section.
#[derive(Default)]
struct Seen {
    auth: String,
    data: String,
}

/// A one-connection SMTP relay on a free port. `auth_reply` answers AUTH PLAIN.
fn fake_smtp(auth_reply: &'static str) -> (u16, JoinHandle<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
    let port = listener.local_addr().expect("has an address").port();
    let handle = thread::spawn(move || {
        let mut seen = Seen::default();
        let (mut sock, _) = listener.accept().expect("accepts");
        sock.write_all(b"220 fake ESMTP\r\n").expect("writes");
        let mut buf: Vec<u8> = Vec::new();
        let mut in_data = false;
        let mut chunk = [0u8; 4096];
        'conn: loop {
            let n = sock.read(&mut chunk).unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if in_data {
                let Some(end) = find(&buf, b"\r\n.\r\n") else { continue };
                seen.data = String::from_utf8_lossy(&buf[..end]).into_owned();
                buf.drain(..end + 5);
                in_data = false;
                sock.write_all(b"250 queued\r\n").expect("writes");
            }
            while !in_data {
                let Some(i) = find(&buf, b"\r\n") else { break };
                let line = String::from_utf8_lossy(&buf[..i]).into_owned();
                buf.drain(..i + 2);
                if line.starts_with("EHLO") {
                    sock.write_all(b"250-fake\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n").expect("writes");
                } else if let Some(credentials) = line.strip_prefix("AUTH PLAIN ") {
                    seen.auth = String::from_utf8_lossy(&base64_decode(credentials).expect("base64")).into_owned();
                    sock.write_all(auth_reply.as_bytes()).expect("writes");
                    if !auth_reply.starts_with("235") {
                        break 'conn;
                    }
                } else if line.starts_with("MAIL FROM:") || line.starts_with("RCPT TO:") {
                    sock.write_all(b"250 ok\r\n").expect("writes");
                } else if line == "DATA" {
                    in_data = true;
                    sock.write_all(b"354 go\r\n").expect("writes");
                } else if line == "QUIT" {
                    let _ = sock.write_all(b"221 bye\r\n");
                    break 'conn;
                } else {
                    sock.write_all(b"500 what\r\n").expect("writes");
                }
            }
        }
        seen
    });
    (port, handle)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn email_config(port: u16) -> Value {
    json!([{ "type": "email", "events": ["case"], "host": "127.0.0.1", "port": port, "security": "none", "user": "ops", "pass": "s3cret-pass", "from": "cvecondor <bot@x>", "to": ["ops@x"] }])
}

/// A fetch double that records every request as (url, headers, body) and answers with `reply`.
type Recorded = Arc<Mutex<Vec<(String, Vec<(String, String)>, Value)>>>;

fn recording(reply: fn(&str) -> Result<Response>) -> (Recorded, impl Fn(Request) -> Result<Response> + Send + Sync) {
    let seen: Recorded = Arc::default();
    let log = seen.clone();
    let fetch = move |req: Request| {
        let body = serde_json::from_slice(req.body.as_deref().unwrap_or(b"null")).unwrap_or(Value::Null);
        log.lock().unwrap_or_else(PoisonError::into_inner).push((req.url.clone(), req.headers.clone(), body));
        reply(&req.url)
    };
    (seen, fetch)
}

fn no_fetch(_: Request) -> Result<Response> {
    Err(anyhow!("this test sends nothing over HTTP"))
}

#[test]
fn email_auth_plain_base64_body_and_rfc2047_subject_over_a_plain_smtp_relay() {
    let (port, server) = fake_smtp("235 ok\r\n");
    let config = test_config(json!({ "notify": email_config(port) }));
    let notice = notice();
    let result = send_notice(&config, &notice, &no_fetch, now());
    assert_eq!(result, SendResult { sent: vec!["email:ops@x".to_string()], errors: vec![] });

    let seen = server.join().expect("the relay finished");
    assert_eq!(seen.auth, "\0ops\0s3cret-pass");
    let (head, body) = seen.data.split_once("\r\n\r\n").expect("headers then body");
    assert!(head.contains("\r\nDate: Wed, 21 Oct 2026 06:00:00 +0000\r\n"), "{head}");
    assert!(head.contains("\r\nMessage-ID: <") && head.contains("@cvecondor>\r\n"), "{head}");
    // The subject: encoded-words, folded; the unfolded join decodes to the title.
    let subject = head
        .split("\r\n")
        .skip_while(|l| !l.starts_with("Subject: "))
        .enumerate()
        .take_while(|(i, l)| *i == 0 || l.starts_with(' '))
        .map(|(_, l)| l)
        .collect::<Vec<_>>();
    let mut decoded = Vec::new();
    for word in subject.join(" ").split("=?UTF-8?B?").skip(1) {
        let (b64, _) = word.split_once("?=").expect("closed encoded-word");
        assert!(b64.len() + 12 <= 75, "word over 75 chars: {word}");
        decoded.extend(base64_decode(b64).expect("base64"));
    }
    assert_eq!(String::from_utf8(decoded).expect("utf-8"), notice.title);
    assert!(body.split("\r\n").all(|l| l.len() <= 76));
    assert_eq!(String::from_utf8(base64_decode(&body.replace("\r\n", "")).expect("base64")).expect("utf-8"), notice.text);
}

#[test]
fn a_rejected_login_reports_the_code_only_never_the_password_or_the_server_text() {
    let (port, server) = fake_smtp("535 bad credentials for s3cret-pass\r\n");
    let config = test_config(json!({ "notify": email_config(port) }));
    let result = send_notice(&config, &notice(), &no_fetch, now());
    server.join().expect("the relay finished");
    assert!(result.sent.is_empty());
    assert_eq!(result.errors, ["email:ops@x: SMTP AUTH: 535"]);
}

#[test]
fn a_notifier_only_receives_the_events_it_lists() {
    let (urls, fetch) = recording(|_| ok("ok"));
    let config = test_config(json!({ "notify": [
        { "type": "telegram", "events": ["report"], "botToken": "123:abc", "chatId": "1" },
        { "type": "webhook", "events": ["case", "report"], "url": "https://hooks.example/n", "headers": {} }
    ] }));
    let result = send_notice(&config, &notice(), &fetch, now());
    assert_eq!(result.sent, ["webhook"]);
    let urls: Vec<String> = urls.lock().unwrap_or_else(PoisonError::into_inner).iter().map(|(u, _, _)| u.clone()).collect();
    assert_eq!(urls, ["https://hooks.example/n"]);
}

#[test]
fn by_default_a_notifier_gets_urgent_notices_only_each_cut_to_one_short_line_with_no_body() {
    let (seen, fetch) = recording(|_| ok("ok"));
    let config = test_config(json!({ "notify": [{ "type": "telegram", "botToken": "123:abc", "chatId": "1" }] }));
    assert_eq!(config.notify[0].events, [NotifyEvent::Urgent]);
    assert!(send_notice(&config, &notice(), &fetch, now()).sent.is_empty(), "a case summary is for the agent in charge, not a push");
    let long = Notice {
        event: NotifyEvent::Urgent,
        title: format!("Act today: left-pad RCE in acme/api:\nworking around it now {}", "x".repeat(400)),
        text: "details that must not be sent".to_string(),
        ..notice()
    };
    assert_eq!(send_notice(&config, &long, &fetch, now()).sent, ["telegram"]);
    let seen = seen.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(seen.len(), 1);
    let text = seen[0].2["text"].as_str().expect("text");
    assert!(text.starts_with("Act today: left-pad RCE in acme/api: working around it now x") && text.ends_with("x…"), "{text}");
    assert_eq!(text.encode_utf16().count(), 300);
}

#[test]
fn a_failing_notifier_reports_without_its_token_or_webhook_url_and_the_others_still_send() {
    let token = "987654:AAH-very-secret-token";
    let slack_url = "https://hooks.slack.com/services/T0/B0/xyzSECRET";
    let fetch = move |req: Request| {
        if req.url.starts_with("https://api.telegram.org/") {
            return status(500, &format!("nope {}", req.url));
        }
        if req.url == slack_url {
            return Err(anyhow!("fetch failed for {}", req.url));
        }
        ok("ok")
    };
    let config = test_config(json!({ "notify": [
        { "type": "telegram", "events": ["case"], "botToken": token, "chatId": "42" },
        { "type": "slack", "events": ["case"], "webhookUrl": slack_url },
        { "type": "webhook", "events": ["case"], "url": "https://hooks.example/n", "headers": {} }
    ] }));
    let result = send_notice(&config, &notice(), &fetch, now());
    assert_eq!(result.sent, ["webhook"]);
    assert_eq!(result.errors.len(), 2);
    assert_eq!(result.errors[0], "telegram: HTTP 500");
    assert_eq!(result.errors[1], "slack: fetch failed for [redacted]");
    for e in &result.errors {
        assert!(!e.contains(token) && !e.contains("very-secret") && !e.contains(slack_url) && !e.contains("xyzSECRET"), "{e}");
    }
}
