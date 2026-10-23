// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! The real HTTP client against a local server: what survives a redirect, what a body's BOM does.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use cvecondor::http::{Fetch, Net, Request, Response};

/// Serves `/a` → 301 `/b` → 200, one connection each, and returns the request heads in order.
fn serve_redirect() -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let handle = thread::spawn(move || {
        let mut heads = Vec::new();
        for reply in [
            "HTTP/1.1 301 Moved Permanently\r\nLocation: /b\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        ] {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut buf).expect("read");
                if n == 0 {
                    break;
                }
                head.extend_from_slice(&buf[..n]);
            }
            heads.push(String::from_utf8_lossy(&head).into_owned());
            stream.write_all(reply.as_bytes()).expect("write");
        }
        heads
    });
    (url, handle)
}

#[test]
fn authorization_survives_a_same_host_redirect() {
    let (url, server) = serve_redirect();
    let response = Net.fetch(Request::get(format!("{url}/a")).header("Authorization", "Bearer abc")).expect("fetches");
    assert_eq!(response.text(), "ok");
    let heads = server.join().expect("server");
    assert_eq!(heads.len(), 2);
    for head in &heads {
        assert!(head.to_ascii_lowercase().contains("authorization: bearer abc"), "a hop lost its Authorization header: {head}");
    }
}

#[test]
fn a_leading_bom_is_not_part_of_the_text_or_the_json() {
    let response = Response { status: 200, headers: Vec::new(), body: b"\xEF\xBB\xBF{\"a\":1}".to_vec() };
    assert_eq!(response.text(), "{\"a\":1}");
    let value: serde_json::Value = response.json().expect("json after the BOM");
    assert_eq!(value["a"], 1);
}
