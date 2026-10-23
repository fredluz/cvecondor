// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! A Docker Engine API endpoint (local socket, tcp or TLS): every container,
//! running or stopped, with its image, OS packages and lockfiles read through
//! the archive endpoint (GET; works on stopped containers and never runs
//! anything inside them), exposure from env/labels/ports, env secrets by name
//! and fingerprint, and running containers' recent logs scanned for secrets.
//! Exec probes (runtime `--version`, `pip list`) run only when the config opts in.
//!
//! A compose project's `.env` and compose YAML live on the host, not in any
//! container, so the API cannot reach them; the host (or ssh) collector scans
//! them when it runs alongside this one.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::CollectContext;
use super::system::{CONTAINER_FILES, ContainerInput, ContainerInspect, EXEC_PROBE, LOG_RISK, TextSource, container_inventory, demux, read_tar, scan_secrets};
use crate::config::DockerCollector;
use crate::http::{Response, raw_request, tls_config, tls_wrap};
use crate::manifests::LOCKFILES;
use crate::secrets::{Exposure, SecretFinding};
use crate::types::{Collected, InventoryItem, ServiceInfo, VendorSignal};

/// Largest response read from the Engine API.
pub const MAX_RESPONSE: usize = 64 << 20;

/// Idle time after which a request is given up.
const TIMEOUT: Duration = Duration::from_secs(60);

enum Target {
    Unix(PathBuf),
    Tcp { host: String, port: u16, tls: Option<Arc<rustls::ClientConfig>> },
}

/// A minimal Engine API client: unversioned paths, JSON bodies, bounded responses, one connection per request.
pub struct DockerClient {
    target: Target,
}

/// `scheme://[user@]host[:port][/path]` → (scheme, host, port, path); the host without IPv6 brackets.
fn parse_endpoint(endpoint: &str) -> Result<(String, String, Option<u16>, String)> {
    let invalid = || anyhow!("Invalid URL");
    // `unix:/var/run/docker.sock` (one slash) is a URL too, and its path is the socket.
    if let Some(path) = endpoint.strip_prefix("unix:").filter(|p| p.starts_with('/') && !p.starts_with("//")) {
        return Ok(("unix".to_string(), String::new(), None, path.split(['?', '#']).next().unwrap_or_default().to_string()));
    }
    let (scheme, rest) = endpoint.split_once("://").ok_or_else(invalid)?;
    if scheme.is_empty() || !scheme.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) {
        return Err(invalid());
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(end);
    let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (host, after) = inner.split_once(']').ok_or_else(invalid)?;
        (host, after.strip_prefix(':').unwrap_or_default())
    } else {
        authority.rsplit_once(':').unwrap_or((authority, ""))
    };
    let port = if port.is_empty() { None } else { Some(port.parse::<u16>().map_err(|_| invalid())?) };
    Ok((scheme.to_ascii_lowercase(), host.to_string(), port, path.split(['?', '#']).next().unwrap_or_default().to_string()))
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| anyhow!("{}: {e}", path.display()))
}

/// The client for a collector's endpoint and TLS files.
pub fn docker_client(config: &DockerCollector) -> Result<DockerClient> {
    let (scheme, host, port, path) = parse_endpoint(&config.endpoint)?;
    let secure = scheme == "https";
    if scheme == "unix" {
        return Ok(DockerClient { target: Target::Unix(PathBuf::from(path)) });
    }
    let tls = if secure {
        let tls = config.tls.clone().unwrap_or_default();
        let ca = tls.ca.as_deref().map(read_file).transpose()?;
        let cert = tls.cert.as_deref().map(read_file).transpose()?;
        let key = tls.key.as_deref().map(read_file).transpose()?;
        let client = match (&cert, &key) {
            (Some(cert), Some(key)) => Some((cert.as_slice(), key.as_slice())),
            _ => None,
        };
        Some(tls_config(ca.as_deref(), client)?)
    } else if scheme != "tcp" && scheme != "http" {
        bail!("unsupported docker endpoint scheme {scheme}:");
    } else {
        None
    };
    Ok(DockerClient { target: Target::Tcp { host, port: port.unwrap_or(if secure { 2376 } else { 2375 }), tls } })
}

fn connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let mut last = None;
    for addr in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(e) => last = Some(e),
        }
    }
    Err(last.map_or_else(|| anyhow!("{host}: no address"), |e| anyhow!("connect {host}:{port}: {e}")))
}

fn exchange<S: Read + Write>(stream: &mut S, method: &str, path: &str, payload: Option<&[u8]>) -> Result<Response> {
    let headers = if payload.is_some() { vec![("content-type".to_string(), "application/json".to_string())] } else { Vec::new() };
    raw_request(stream, method, "docker", path, &headers, payload, MAX_RESPONSE)
}

/// Socket timeouts and oversize responses read as the TS reports them: `<path>: timed out`, `<path>: response over N bytes`.
fn describe(path: &str, error: anyhow::Error) -> anyhow::Error {
    let bare = path.split('?').next().unwrap_or(path);
    let timed_out = error
        .chain()
        .any(|e| e.downcast_ref::<std::io::Error>().is_some_and(|io| matches!(io.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)));
    if timed_out {
        anyhow!("{bare}: timed out")
    } else if error.to_string().starts_with("response over") {
        anyhow!("{bare}: response over {MAX_RESPONSE} bytes")
    } else {
        error
    }
}

impl DockerClient {
    /// One request. `timeout` (default 60 s) is the longest the connection may be idle.
    pub fn request(&self, method: &str, path: &str, body: Option<&Value>, timeout: Option<Duration>) -> Result<Response> {
        let timeout = timeout.unwrap_or(TIMEOUT);
        let payload = body.map(serde_json::to_vec).transpose()?;
        let payload = payload.as_deref();
        let result = match &self.target {
            Target::Unix(socket) => {
                let mut stream = UnixStream::connect(socket).map_err(|e| anyhow!("connect {}: {e}", socket.display()))?;
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
                exchange(&mut stream, method, path, payload)
            }
            Target::Tcp { host, port, tls } => {
                let mut tcp = connect(host, *port, timeout)?;
                tcp.set_read_timeout(Some(timeout))?;
                tcp.set_write_timeout(Some(timeout))?;
                match tls {
                    Some(config) => exchange(&mut tls_wrap(tcp, host, config.clone())?, method, path, payload),
                    None => exchange(&mut tcp, method, path, payload),
                }
            }
        };
        result.map_err(|e| describe(path, e))
    }

    /// GET a JSON document; anything but 200 is an error.
    fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let res = self.request("GET", path, None, None)?;
        if res.status != 200 {
            bail!("GET {}: HTTP {}", path.split('?').next().unwrap_or(path), res.status);
        }
        Ok(serde_json::from_slice(&res.body)?)
    }
}

/// JS `encodeURIComponent`.
pub fn encode_uri_component(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A file from a container's filesystem via the archive endpoint; `None` when absent (or a symlink).
fn container_file(client: &DockerClient, id: &str, path: &str) -> Result<Option<String>> {
    let res = client.request("GET", &format!("/containers/{id}/archive?path={}", encode_uri_component(path)), None, None)?;
    if res.status != 200 {
        return Ok(None);
    }
    Ok(read_tar(&res.body).first().map(|entry| String::from_utf8_lossy(entry.data).into_owned()))
}

fn exec_probe(client: &DockerClient, id: &str) -> Result<String> {
    let created = client.request(
        "POST",
        &format!("/containers/{id}/exec"),
        Some(&json!({ "AttachStdout": true, "AttachStderr": true, "Cmd": ["sh", "-c", EXEC_PROBE] })),
        None,
    )?;
    if created.status != 201 {
        return Ok(String::new());
    }
    #[derive(Deserialize)]
    struct Created {
        #[serde(rename = "Id")]
        id: String,
    }
    let exec: Created = created.json()?;
    let started =
        client.request("POST", &format!("/exec/{}/start", exec.id), Some(&json!({ "Detach": false, "Tty": false })), Some(Duration::from_secs(90)))?;
    Ok(if started.status == 200 { demux(&started.body) } else { String::new() })
}

#[derive(Deserialize)]
struct ListEntry {
    #[serde(rename = "Id")]
    id: String,
}

#[derive(Deserialize)]
struct ImageInspect {
    #[serde(rename = "Config", default)]
    config: Option<ImageConfig>,
}

#[derive(Deserialize)]
struct ImageConfig {
    #[serde(rename = "Env", default)]
    env: Option<Vec<String>>,
}

/// What a collection pass has gathered so far.
#[derive(Default)]
struct Gathered {
    items: Vec<InventoryItem>,
    services: Vec<ServiceInfo>,
    secrets: Vec<SecretFinding>,
    signals: Vec<VendorSignal>,
    warnings: Vec<String>,
    logs: Vec<TextSource>,
}

/// One container's inventory (and log text) added to `out`; an error leaves what was added before it.
fn collect_container(
    client: &DockerClient,
    config: &DockerCollector,
    id: &str,
    images: &mut HashMap<String, Option<Vec<String>>>,
    out: &mut Gathered,
) -> Result<()> {
    let host = config.name.as_str();
    let c: ContainerInspect = client.get_json(&format!("/containers/{id}/json"))?;
    let image_env = images
        .entry(c.image.clone())
        .or_insert_with(|| {
            client.get_json::<ImageInspect>(&format!("/images/{}/json", encode_uri_component(&c.image))).ok().and_then(|i| i.config).and_then(|c| c.env)
        })
        .clone();
    let mut files = indexmap::IndexMap::new();
    for path in CONTAINER_FILES.os_release {
        if let Some(text) = container_file(client, id, path)?.filter(|t| !t.is_empty()) {
            files.insert(path.to_string(), text);
            break;
        }
    }
    let working_dir = c.config.working_dir.as_deref().filter(|w| !w.is_empty()).unwrap_or("/");
    let working_dir = working_dir.strip_suffix('/').unwrap_or(working_dir);
    let paths = [CONTAINER_FILES.dpkg.to_string(), CONTAINER_FILES.apk.to_string()].into_iter().chain(LOCKFILES.iter().map(|f| format!("{working_dir}/{f}")));
    for path in paths {
        if let Some(text) = container_file(client, id, &path)? {
            files.insert(path, text);
        }
    }
    let running = c.state.status == "running";
    let probe = if config.exec && running {
        match exec_probe(client, id) {
            Ok(probe) => probe,
            Err(error) => {
                out.warnings.push(format!("{}: exec probe failed: {error}", c.name));
                String::new()
            }
        }
    } else {
        String::new()
    };
    let result = container_inventory(host, &c, &ContainerInput { image_env, files, probe: Some(probe) });
    out.items.extend(result.items);
    out.services.extend(result.services);
    out.secrets.extend(result.secrets);
    out.signals.extend(result.signals);
    if running {
        let res = client.request("GET", &format!("/containers/{id}/logs?stdout=1&stderr=1&tail=2000"), None, None)?;
        if res.status == 200 {
            out.logs.push(TextSource {
                r#where: format!("container:{}", c.name.strip_prefix('/').unwrap_or(&c.name)),
                location: "logs".to_string(),
                text: if c.config.tty == Some(true) { String::from_utf8_lossy(&res.body).into_owned() } else { demux(&res.body) },
                exposure: Exposure::Log,
                risk: LOG_RISK.to_string(),
                env: None,
            });
        }
    }
    Ok(())
}

pub fn collect_docker(config: &DockerCollector, context: &CollectContext) -> Result<Collected> {
    let client = docker_client(config)?;
    let host = config.name.as_str();
    let list: Vec<ListEntry> = client.get_json("/containers/json?all=1")?;
    let mut out = Gathered::default();
    let mut images: HashMap<String, Option<Vec<String>>> = HashMap::new();
    for ListEntry { id } in &list {
        if let Err(error) = collect_container(&client, config, id, &mut images, &mut out) {
            out.warnings.push(format!("container {}: {error}", id.chars().take(12).collect::<String>()));
        }
    }
    (context.log)(&format!("{host}: {} containers, {} items", list.len(), out.items.len()));
    let logged = scan_secrets(host, &out.logs, &mut out.warnings);
    out.secrets.extend(logged);
    Ok(Collected { items: out.items, services: out.services, secrets: out.secrets, signals: out.signals, warnings: out.warnings })
}
