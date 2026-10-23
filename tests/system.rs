// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! System collectors: container secret safety, dpkg source names, tar, the ssh
//! section parser, and real runs of `collect_host` on a fake root and
//! `collect_docker` against a fake Engine API on a unix socket.

mod common;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use common::TempDir;
use cvecondor::config::{DockerCollector, HostCollector};
use cvecondor::http::Net;
use cvecondor::inventory::CollectContext;
use cvecondor::inventory::docker::collect_docker;
use cvecondor::inventory::host::collect_host;
use cvecondor::inventory::ssh::{ScriptOptions, parse_ssh, ssh_script};
use cvecondor::inventory::system::{Base, ContainerInput, ContainerInspect, container_inventory, dpkg_status_items, read_tar};
use cvecondor::secrets::{Exposure, gitleaks_available};
use cvecondor::types::{ItemKind, VendorSignalKind};
use indexmap::IndexMap;
use serde_json::{Value, json};

const OPENROUTER: &str = "sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef";
const DB_URL: &str = "postgres://u:hunter2pass@db.abcdefgh.supabase.co/x";
const GHP: &str = concat!("ghp_", "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gI3kM5");

fn context<'a>(dir: &'a std::path::Path, net: &'a Net) -> CollectContext<'a> {
    CollectContext { state_dir: dir, fetch: net, log: &|_| {}, previous: None }
}

fn inspect_json() -> Value {
    json!({
        "Id": "abc123", "Name": "/web", "Image": "sha256:img", "State": { "Status": "running" },
        "Config": {
            "Image": "ghcr.io/acme/web:1.4", "WorkingDir": "/app",
            "Env": ["PATH=/usr/bin", format!("OPENROUTER_API_KEY={OPENROUTER}"), format!("DATABASE_URL={DB_URL}"), "VIRTUAL_HOST=app.example.com", "NODE_VERSION=22.11.0"],
            "Labels": { "com.docker.compose.project.working_dir": "/opt/web" }
        },
        "HostConfig": { "RestartPolicy": { "Name": "unless-stopped" } },
        "NetworkSettings": { "Ports": { "80/tcp": [{ "HostIp": "0.0.0.0", "HostPort": "8080" }], "9000/tcp": [{ "HostIp": "127.0.0.1", "HostPort": "9000" }] } }
    })
}

fn inspect() -> ContainerInspect {
    serde_json::from_value(inspect_json()).expect("inspect parses")
}

/// A ustar archive of regular files.
fn tar(files: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, text) in files {
        let data = text.as_bytes();
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
        header[148..156].copy_from_slice(b"        ");
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        let sum: u32 = header.iter().map(|&b| u32::from(b)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(data);
        out.resize(out.len() + (512 - data.len() % 512) % 512, 0);
    }
    out.resize(out.len() + 1024, 0);
    out
}

const DPKG: &str = "Package: libssl3t64
Status: install ok installed
Source: openssl (3.0.13-0ubuntu3.4)
Version: 3.0.13-0ubuntu3.4

Package: bash
Status: install ok installed
Version: 5.2.21-2ubuntu4

Package: gone
Status: deinstall ok config-files
Version: 1.0

Package: zlib1g
Status: install ok installed
Source: zlib
Version: 1:1.3.dfsg-3.1ubuntu2
";
const UBUNTU: &str = "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nVERSION=\"24.04.1 LTS (Noble Numbat)\"\nID=ubuntu\n";

fn is_fingerprint(f: Option<&str>) -> bool {
    f.is_some_and(|f| f.len() == 8 && f.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

#[test]
fn container_env_secrets_are_names_and_fingerprints_only_exposure_from_virtual_host_and_public_ports() {
    let files = IndexMap::from([("/etc/os-release".to_string(), UBUNTU.to_string()), ("/var/lib/dpkg/status".to_string(), DPKG.to_string())]);
    let result = container_inventory("web1", &inspect(), &ContainerInput { files, ..ContainerInput::default() });
    let text = format!("{result:?}");
    for secret in [OPENROUTER, DB_URL, "hunter2pass", "abcdefgh"] {
        assert!(!text.contains(secret), "secret value leaked");
    }
    let mut names: Vec<_> = result.secrets.iter().map(|s| (s.name.clone().unwrap_or_default(), s.exposure, is_fingerprint(s.fingerprint.as_deref()))).collect();
    names.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(names, [("DATABASE_URL".to_string(), Exposure::ContainerEnv, true), ("OPENROUTER_API_KEY".to_string(), Exposure::ContainerEnv, true)]);
    assert_eq!(result.services[0].exposed, ["app.example.com", "0.0.0.0:8080->80/tcp"]);
    assert_eq!(result.services[0].compose.as_deref(), Some("/opt/web"));
    let mut env_names: Vec<_> = result.signals.iter().filter(|s| s.kind == VendorSignalKind::Env).map(|s| s.value.as_str()).collect();
    env_names.sort();
    assert_eq!(env_names, ["DATABASE_URL", "OPENROUTER_API_KEY", "VIRTUAL_HOST"]);
    assert!(result.signals.iter().any(|s| s.kind == VendorSignalKind::Hostname && s.value == "supabase.co"));
    assert!(result.items.iter().any(|i| i.kind == ItemKind::Runtime && i.name == "node" && i.version == "22.11.0"));
    assert!(
        result
            .items
            .iter()
            .any(|i| i.kind == ItemKind::OsPackage && i.name == "openssl" && i.ecosystem.as_deref() == Some("Ubuntu:24.04:LTS") && i.running == Some(true))
    );
}

#[test]
fn an_official_runtime_image_that_sets_no_version_in_its_env_counts_the_version_its_tag_names() {
    let mut raw = inspect_json();
    raw["Config"]["Image"] = json!("oven/bun:1.3.5-alpine");
    let bun: ContainerInspect = serde_json::from_value(raw).expect("inspect parses");
    let result = container_inventory("web1", &bun, &ContainerInput::default());
    let runtimes: Vec<_> = result.items.iter().filter(|i| i.kind == ItemKind::Runtime).map(|i| (i.name.as_str(), i.version.as_str())).collect();
    assert_eq!(runtimes, [("node", "22.11.0"), ("bun", "1.3.5")]);
    // The env's version wins over the tag's.
    let mut raw = inspect_json();
    raw["Config"]["Image"] = json!("node:22-alpine");
    let node: ContainerInspect = serde_json::from_value(raw).expect("inspect parses");
    let result = container_inventory("web1", &node, &ContainerInput::default());
    let runtimes: Vec<_> = result.items.iter().filter(|i| i.kind == ItemKind::Runtime).map(|i| (i.name.as_str(), i.version.as_str())).collect();
    assert_eq!(runtimes, [("node", "22.11.0")]);
}

#[test]
fn dpkg_status_source_package_names_and_versions_installed_only() {
    let items = dpkg_status_items(DPKG, Base { ecosystem: Some("Ubuntu:24.04:LTS"), ..Base::new("h", "host") });
    let got: Vec<_> = items.iter().map(|i| (i.name.as_str(), i.version.as_str(), i.path.as_deref().unwrap_or(""))).collect();
    assert_eq!(got, [("openssl", "3.0.13-0ubuntu3.4", "libssl3t64"), ("bash", "5.2.21-2ubuntu4", "bash"), ("zlib", "1:1.3.dfsg-3.1ubuntu2", "zlib1g")]);
}

#[test]
fn tar_reader_extracts_regular_files() {
    let archive = tar(&[("os-release", UBUNTU), ("app/package-lock.json", "{}")]);
    let files = read_tar(&archive);
    let got: Vec<_> = files.iter().map(|f| (f.name.as_str(), String::from_utf8_lossy(f.data).into_owned())).collect();
    assert_eq!(got, [("os-release", UBUNTU.to_string()), ("app/package-lock.json", "{}".to_string())]);
}

#[test]
fn ssh_output_host_packages_runtimes_containers_files_script_is_valid_sh() {
    for options in [ScriptOptions { sudo: true, docker: true }, ScriptOptions { sudo: false, docker: false }] {
        let mut child = Command::new("sh").arg("-n").stdin(Stdio::piped()).spawn().expect("sh starts");
        child.stdin.take().expect("piped").write_all(ssh_script(options).as_bytes()).expect("script written");
        assert!(child.wait().expect("sh exits").success(), "sh -n rejected the script");
    }
    let pipe = |s: &str| s.split('\n').map(|l| format!("|{l}")).collect::<Vec<_>>().join("\n");
    let output = [
        String::new(),
        "@@os@@".to_string(),
        pipe(UBUNTU),
        "@@kernel@@".to_string(),
        "|6.8.0-45-generic".to_string(),
        "@@dpkg@@".to_string(),
        pipe("libssl3t64\t3.0.13-0ubuntu3.4\topenssl\t3.0.13-0ubuntu3.4\tii \nold\t1\told\t1\trc "),
        "@@hostbin@@".to_string(),
        "|/usr/bin/node\tv20.18.0".to_string(),
        "@@containers@@".to_string(),
        format!("|{}", inspect_json()),
        "@@cfile abc123 /etc/os-release@@".to_string(),
        pipe("ID=alpine\nVERSION_ID=3.22.1\nPRETTY_NAME=\"Alpine Linux v3.22\""),
        "@@cfile abc123 /lib/apk/db/installed@@".to_string(),
        pipe("P:libcrypto3\nV:3.5.1-r0\no:openssl\n\nP:musl\nV:1.2.5-r10\n"),
        "@@cfile abc123 /app/package-lock.json@@".to_string(),
        pipe("{\"packages\":{\"node_modules/lodash\":{\"version\":\"4.17.20\"}}}"),
        "@@logs abc123@@".to_string(),
        "|@@end@@".to_string(),
        "|started".to_string(),
        "@@file 644 /opt/web/.env@@".to_string(),
        pipe(&format!("API_TOKEN={GHP}")),
        "@@venvs@@".to_string(),
        pipe("/opt/worker/.venv/lib/python3.12/site-packages/Brotli-1.2.0.dist-info\n/opt/worker/.venv/lib/python3.12/site-packages/not-a-dist-info"),
        "@@end@@".to_string(),
        String::new(),
    ]
    .join("\n");
    let r = parse_ssh("web1", &output).expect("parses");
    let has = |place: &str, name: &str, version: &str| r.collected.items.iter().any(|i| i.r#where == place && i.name == name && i.version == version);
    assert!(has("host", "openssl", "3.0.13-0ubuntu3.4") && !has("host", "old", "1"));
    assert!(has("host", "linux kernel", "6.8.0-45-generic") && has("host", "node", "20.18.0"));
    assert!(r.collected.items.iter().any(|i| i.r#where == "container:web" && i.name == "openssl" && i.ecosystem.as_deref() == Some("Alpine:v3.22")));
    assert!(has("container:web", "lodash", "4.17.20"));
    let venv: Vec<_> = r.collected.items.iter().filter(|i| i.ecosystem.as_deref() == Some("PyPI")).map(|i| (i.r#where.as_str(), i.name.as_str(), i.version.as_str(), i.path.as_deref())).collect();
    assert_eq!(venv, [("host", "Brotli", "1.2.0", Some("/opt/worker/.venv"))]);
    assert_eq!(r.collected.services[0].r#where, "container:web");
    let sources: Vec<_> = r.sources.iter().map(|s| (s.location.as_str(), s.exposure)).collect();
    assert_eq!(sources, [("logs", Exposure::Log), ("/opt/web/.env", Exposure::HostFile)]);
    assert!(r.collected.signals.iter().any(|s| s.kind == VendorSignalKind::Env && s.value == "API_TOKEN" && s.path.as_deref() == Some("/opt/web/.env")));
}

#[test]
fn ssh_output_without_the_end_marker_is_cut_short() {
    let error = parse_ssh("web1", "\n@@os@@\n|ID=debian\n").expect_err("no end marker");
    assert_eq!(error.to_string(), "remote collection was cut short (no end marker)");
}

/// Found live: with a `sudo` that only allows `cat`/`find`, the `--version` probes ran under sudo and every runtime
/// vanished; and with `docker ps` refused (no docker group, no sudo rule) the containers vanished without a word.
#[test]
fn ssh_script_probes_versions_without_sudo_and_reports_a_refused_docker() {
    let bin = TempDir::new("cvw-ssh-bin");
    let tool = |name: &str, body: &str| {
        let path = bin.path().join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("tool written");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("tool executable");
    };
    tool("sudo", "echo 'sudo: a password is required' >&2; exit 1");
    tool("docker", "echo 'permission denied while trying to connect to the docker API' >&2; exit 1");
    tool("node", "echo v20.1.0");
    let mut child = Command::new("sh")
        .arg("-s")
        .env("PATH", format!("{}:/usr/bin:/bin", bin.path().display()))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("sh starts");
    child.stdin.take().expect("piped").write_all(ssh_script(ScriptOptions { sudo: true, docker: true }).as_bytes()).expect("script written");
    let output = String::from_utf8_lossy(&child.wait_with_output().expect("sh exits").stdout).into_owned();
    let r = parse_ssh("web1", &output).expect("parses");
    assert!(r.collected.items.iter().any(|i| i.name == "node" && i.version == "20.1.0"), "runtime probed without sudo");
    assert_eq!(r.collected.warnings.len(), 1);
    assert!(r.collected.warnings[0].contains("docker ps") && r.collected.warnings[0].contains("a password is required"), "{:?}", r.collected.warnings);
}

#[test]
fn collect_host_on_a_fake_debian_root_packages_and_a_world_readable_env_secret_by_fingerprint() {
    let root = TempDir::new("cvw-host");
    let at = |p: &str| root.path().join(p);
    for dir in ["etc", "var/lib/dpkg", "opt/app", "opt/app/.venv/lib/python3.12/site-packages/Brotli-1.2.0.dist-info", "opt/worker/lib/python3.11/site-packages/brotlicffi-1.2.0.1.dist-info"] {
        std::fs::create_dir_all(at(dir)).expect("mkdir");
    }
    std::fs::write(at("etc/os-release"), "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\r\nID=\"debian\"\r\nVERSION_ID=\"12\"\r\n").expect("write");
    std::fs::write(at("var/lib/dpkg/status"), DPKG).expect("write");
    std::fs::write(at("opt/app/.env"), format!("PORT=3000\nGITHUB_TOKEN={GHP}\n")).expect("write");
    std::fs::set_permissions(at("opt/app/.env"), std::fs::Permissions::from_mode(0o644)).expect("chmod");
    let net = Net;
    let config = HostCollector { name: "box".to_string(), root: root.path().to_path_buf(), binaries: Vec::new() };
    let r = collect_host(&config, &context(root.path(), &net)).expect("collects");
    assert!(r.items.iter().any(|i| i.name == "openssl" && i.ecosystem.as_deref() == Some("Debian:12")));
    assert!(r.items.iter().any(|i| i.kind == ItemKind::Os && i.name == "Debian GNU/Linux 12 (bookworm)"));
    let mut venvs: Vec<_> = r.items.iter().filter(|i| i.ecosystem.as_deref() == Some("PyPI")).map(|i| (i.name.as_str(), i.version.as_str(), i.path.as_deref())).collect();
    venvs.sort_unstable();
    assert_eq!(venvs, [("Brotli", "1.2.0", Some("/opt/app/.venv")), ("brotlicffi", "1.2.0.1", Some("/opt/worker"))], "a venv in a project dir, or the dir itself");
    let hit = r.secrets.iter().find(|s| s.exposure == Exposure::HostFile && s.location == "/opt/app/.env").expect("the .env secret");
    assert!(is_fingerprint(hit.fingerprint.as_deref()) && hit.line == Some(2) && hit.risk.contains("World-readable"));
    assert!(!format!("{r:?}").contains(GHP));
}

/// Percent-decodes a query value.
fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(b) = u8::from_str_radix(&text[i + 1..i + 3], 16)
        {
            out.push(b);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Reads one request head; returns its method and target.
fn read_request(stream: &mut impl Read) -> Option<(String, String)> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).ok()? == 0 {
            return None;
        }
        head.push(byte[0]);
    }
    let line = String::from_utf8_lossy(&head).lines().next()?.to_string();
    let mut parts = line.split(' ');
    Some((parts.next()?.to_string(), parts.next()?.to_string()))
}

#[test]
fn collect_docker_against_a_fake_engine_api_on_a_unix_socket() {
    let dir = TempDir::new("cvw-docker");
    let socket = dir.path().join("docker.sock");
    let log = format!("boot\nusing GITHUB_TOKEN={GHP}\n");
    let mut logs = vec![1, 0, 0, 0];
    logs.extend_from_slice(&u32::try_from(log.len()).expect("small").to_be_bytes());
    logs.extend_from_slice(log.as_bytes());
    let listener = UnixListener::bind(&socket).expect("binds");
    listener.set_nonblocking(true).expect("nonblocking");
    let stop = Arc::new(AtomicBool::new(false));
    let routes: HashMap<&str, Vec<u8>> = HashMap::from([
        ("/etc/os-release", tar(&[("os-release", UBUNTU)])),
        ("/var/lib/dpkg/status", tar(&[("status", DPKG)])),
        ("/app/package-lock.json", tar(&[("package-lock.json", "{\"packages\":{\"node_modules/lodash\":{\"version\":\"4.17.20\"}}}")])),
    ]);
    let server = {
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let Ok((mut stream, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(2));
                    continue;
                };
                stream.set_nonblocking(false).expect("blocking");
                let Some((method, target)) = read_request(&mut stream) else { continue };
                let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));
                let file = query.split('&').find_map(|q| q.strip_prefix("path=")).map(decode);
                let (status, body): (u16, Vec<u8>) = if method != "GET" {
                    (405, Vec::new())
                } else if path == "/containers/json" {
                    (200, json!([{ "Id": "abc123" }]).to_string().into_bytes())
                } else if path == "/containers/abc123/json" {
                    (200, inspect_json().to_string().into_bytes())
                } else if path == "/images/sha256%3Aimg/json" || path == "/images/sha256:img/json" {
                    (200, json!({ "Config": { "Env": ["PYTHON_VERSION=3.12.4"] } }).to_string().into_bytes())
                } else if path == "/containers/abc123/logs" {
                    (200, logs.clone())
                } else if let Some(archive) = file.as_deref().and_then(|f| routes.get(f)) {
                    (200, archive.clone())
                } else {
                    (404, b"{}".to_vec())
                };
                let head = format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
            }
        })
    };
    let net = Net;
    let config = DockerCollector { name: "local".to_string(), endpoint: format!("unix://{}", socket.display()), tls: None, exec: false };
    let result = collect_docker(&config, &context(dir.path(), &net));
    stop.store(true, Ordering::SeqCst);
    server.join().expect("server stops");
    let r = result.expect("collects");
    assert!(r.items.iter().any(|i| i.name == "openssl" && i.ecosystem.as_deref() == Some("Ubuntu:24.04:LTS")));
    assert!(r.items.iter().any(|i| i.name == "lodash" && i.path.as_deref() == Some("/app/package-lock.json")));
    assert!(r.items.iter().any(|i| i.name == "python" && i.version == "3.12.4"));
    if gitleaks_available() {
        assert!(r.secrets.iter().any(|s| s.exposure == Exposure::Log && s.r#where == "container:web" && is_fingerprint(s.fingerprint.as_deref())));
    } else {
        println!("gitleaks is not installed: the log secret assertion is skipped");
    }
    let text = format!("{r:?}");
    for secret in [GHP, OPENROUTER, DB_URL] {
        assert!(!text.contains(secret));
    }
}

#[test]
fn a_bom_before_the_first_env_variable_keeps_its_signal_and_its_secret_name() {
    let root = TempDir::new("cvw-bom");
    let at = |p: &str| root.path().join(p);
    for dir in ["etc", "opt/app"] {
        std::fs::create_dir_all(at(dir)).expect("mkdir");
    }
    std::fs::write(at("etc/os-release"), "ID=debian\n").expect("write");
    std::fs::write(at("opt/app/.env"), format!("\u{feff}VERCEL_TOKEN={GHP}\nPORT=3000\n")).expect("write");
    let net = Net;
    let config = HostCollector { name: "box".to_string(), root: root.path().to_path_buf(), binaries: Vec::new() };
    let r = collect_host(&config, &context(root.path(), &net)).expect("collects");
    assert!(r.signals.iter().any(|s| s.kind == VendorSignalKind::Env && s.value == "VERCEL_TOKEN"), "{:?}", r.signals);
    let names: Vec<_> = r.secrets.iter().filter(|s| s.location == "/opt/app/.env").map(|s| s.name.as_deref()).collect();
    assert_eq!(names, [Some("VERCEL_TOKEN")]);
}

#[test]
fn a_unix_endpoint_with_one_slash_names_the_socket() {
    let config = DockerCollector { name: "local".to_string(), endpoint: "unix:/nonexistent/docker.sock".to_string(), tls: None, exec: false };
    let client = cvecondor::inventory::docker::docker_client(&config).expect("unix:/path is an endpoint");
    let error = client.request("GET", "/containers/json", None, None).err().expect("no daemon there");
    assert!(error.to_string().starts_with("connect /nonexistent/docker.sock:"), "{error}");
}
