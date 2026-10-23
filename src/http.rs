// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! HTTP for the watcher: a `Fetch` trait every network caller takes (tests pass
//! closures), the real client over ureq, TLS helpers for the SMTP and Docker
//! clients, and a bare HTTP/1.1 exchange over any stream (the Docker socket).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::de::DeserializeOwned;

use crate::name::USER_AGENT;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
const BODY_LIMIT: u64 = 512 << 20;

pub struct Request {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub timeout: Option<Duration>,
}

impl Request {
    pub fn get(url: impl Into<String>) -> Self {
        Self { method: "GET".into(), url: url.into(), headers: Vec::new(), body: None, timeout: None }
    }

    pub fn post(url: impl Into<String>, body: Vec<u8>) -> Self {
        Self { method: "POST".into(), url: url.into(), headers: Vec::new(), body: Some(body), timeout: None }
    }

    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((key.into(), value.into()));
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

pub struct Response {
    pub status: u16,
    /// Names lower-cased.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// 200..=299.
    pub fn ok(&self) -> bool {
        (200..=299).contains(&self.status)
    }

    /// The body as text, invalid UTF-8 replaced, a leading BOM dropped (as `fetch().text()` does).
    pub fn text(&self) -> String {
        let text = String::from_utf8_lossy(&self.body);
        text.strip_prefix('\u{feff}').unwrap_or(&text).to_string()
    }

    /// The body as JSON; a leading UTF-8 BOM is skipped (as `fetch().json()` does).
    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        let body = self.body.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&self.body);
        serde_json::from_slice(body).context("invalid JSON in response body")
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// Everything that talks to the network takes one of these. A non-2xx status is an `Ok(Response)`;
/// only a transport failure (DNS, connect, TLS, timeout) is an `Err`.
pub trait Fetch: Send + Sync {
    fn fetch(&self, req: Request) -> Result<Response>;
}

impl<F: Fn(Request) -> Result<Response> + Send + Sync> Fetch for F {
    fn fetch(&self, req: Request) -> Result<Response> {
        self(req)
    }
}

/// The real client: follows redirects (keeping `Authorization` on the same host, never across hosts), never turns a
/// status into an error, sends `User-Agent: cvecondor/<version>` unless the request sets its own, ignores proxy
/// variables (like Node's `fetch`). Trusts the bundled web roots plus the PEM bundles `SSL_CERT_FILE` and
/// `NODE_EXTRA_CA_CERTS` name (a private CA for an internal host).
pub struct Net;

/// The PEM bundles `SSL_CERT_FILE` and `NODE_EXTRA_CA_CERTS` point at, as certificates. An unset, unreadable or
/// certificate-free file adds nothing.
fn extra_ca_certs() -> Vec<CertificateDer<'static>> {
    let mut certs = Vec::new();
    for var in ["SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS"] {
        let Some(path) = std::env::var_os(var).filter(|p| !p.is_empty()) else { continue };
        if let Ok(pem) = std::fs::read(path) {
            certs.extend(CertificateDer::pem_slice_iter(&pem).filter_map(|cert| cert.ok()));
        }
    }
    certs
}

/// `extra`: trust exactly these certificates (the retry after the web roots refused a host's certificate).
fn agent(extra: Option<&[CertificateDer<'static>]>) -> ureq::Agent {
    let mut config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(10)
        .redirect_auth_headers(ureq::config::RedirectAuthHeaders::SameHost)
        .proxy(None)
        .user_agent(USER_AGENT)
        .timeout_global(Some(DEFAULT_TIMEOUT));
    if let Some(certs) = extra {
        let certs: Vec<ureq::tls::Certificate<'static>> = certs.iter().map(|c| ureq::tls::Certificate::from_der(c.as_ref()).to_owned()).collect();
        config = config.tls_config(ureq::tls::TlsConfig::builder().root_certs(ureq::tls::RootCerts::new_with_certs(&certs)).build());
    }
    ureq::Agent::new_with_config(config.build())
}

/// Why an exchange failed; `untrusted`: the server's certificate chains to none of the roots.
struct Failure {
    message: String,
    untrusted: bool,
}

fn untrusted_certificate(error: &ureq::Error) -> bool {
    let is_cert = |e: &rustls::Error| matches!(e, rustls::Error::InvalidCertificate(_));
    match error {
        ureq::Error::Rustls(e) => is_cert(e),
        ureq::Error::Io(e) => e.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()).is_some_and(is_cert),
        _ => false,
    }
}

fn send<S: ureq::AsSendBody>(agent: &ureq::Agent, request: ureq::http::Request<S>, timeout: Option<Duration>) -> std::result::Result<Response, Failure> {
    let request = agent.configure_request(request).timeout_global(Some(timeout.unwrap_or(DEFAULT_TIMEOUT))).build();
    // Neither the URL nor the body goes into the message: both can carry a secret (a webhook URL).
    let mut response = agent.run(request).map_err(|e| Failure { message: format!("request failed: {e}"), untrusted: untrusted_certificate(&e) })?;
    let status = response.status().as_u16();
    let headers =
        response.headers().iter().map(|(name, value)| (name.as_str().to_ascii_lowercase(), String::from_utf8_lossy(value.as_bytes()).into_owned())).collect();
    let body = response
        .body_mut()
        .with_config()
        .limit(BODY_LIMIT)
        .read_to_vec()
        .map_err(|e| Failure { message: format!("reading the response failed: {e}"), untrusted: false })?;
    Ok(Response { status, headers, body })
}

fn exchange(agent: &ureq::Agent, req: &Request) -> std::result::Result<Response, Failure> {
    let invalid = |e: ureq::http::Error| Failure { message: format!("invalid request: {e}"), untrusted: false };
    let mut builder = ureq::http::Request::builder().method(req.method.as_str()).uri(req.url.as_str());
    for (key, value) in &req.headers {
        builder = builder.header(key.as_str(), value.as_str());
    }
    match req.body.as_deref() {
        Some(body) => send(agent, builder.body(body).map_err(invalid)?, req.timeout),
        None => send(agent, builder.body(()).map_err(invalid)?, req.timeout),
    }
}

impl Fetch for Net {
    fn fetch(&self, req: Request) -> Result<Response> {
        match exchange(&agent(None), &req) {
            Ok(response) => Ok(response),
            // The web roots refused the certificate: a private CA the user named may vouch for it. Nothing was sent yet.
            Err(Failure { untrusted: true, message }) => {
                let extra = extra_ca_certs();
                if extra.is_empty() {
                    return Err(anyhow!(message));
                }
                exchange(&agent(Some(&extra)), &req).map_err(|f| anyhow!(f.message))
            }
            Err(failure) => Err(anyhow!(failure.message)),
        }
    }
}

// ---------- TLS ----------

/// A TLS client configuration. `ca_pem`: trust exactly these certificates (a private CA);
/// `None`: the bundled web roots. `client`: certificate chain and private key (PEM) for mutual TLS.
pub fn tls_config(ca_pem: Option<&[u8]>, client: Option<(&[u8], &[u8])>) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    match ca_pem {
        Some(pem) => {
            let mut added = 0;
            for cert in CertificateDer::pem_slice_iter(pem) {
                roots.add(cert.context("invalid CA certificate")?).context("invalid CA certificate")?;
                added += 1;
            }
            if added == 0 {
                bail!("no certificate found in the CA file");
            }
        }
        None => {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            // Like Node's `NODE_EXTRA_CA_CERTS`: the web roots stay, the bundle's certificates join them.
            let _ = roots.add_parsable_certificates(extra_ca_certs());
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions()?.with_root_certificates(roots);
    let config = match client {
        Some((cert_pem, key_pem)) => {
            let chain = CertificateDer::pem_slice_iter(cert_pem).collect::<Result<Vec<_>, _>>().context("invalid client certificate")?;
            if chain.is_empty() {
                bail!("no certificate found in the client certificate file");
            }
            let key = PrivateKeyDer::from_pem_slice(key_pem).context("invalid client key")?;
            builder.with_client_auth_cert(chain, key).context("client certificate and key do not match")?
        }
        None => builder.with_no_client_auth(),
    };
    Ok(Arc::new(config))
}

pub type TlsStream = StreamOwned<ClientConnection, TcpStream>;

/// Runs the TLS handshake over `tcp` against `server_name` (a DNS name or an IP address).
pub fn tls_wrap(mut tcp: TcpStream, server_name: &str, config: Arc<ClientConfig>) -> Result<TlsStream> {
    let name = ServerName::try_from(server_name.to_string()).map_err(|_| anyhow!("invalid TLS server name {server_name}"))?;
    let mut conn = ClientConnection::new(config, name)?;
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp).context("TLS handshake failed")?;
    }
    Ok(StreamOwned::new(conn, tcp))
}

// ---------- raw HTTP/1.1 ----------

fn read_line<R: BufRead>(reader: &mut R) -> Result<String> {
    let mut line = Vec::new();
    reader.read_until(b'\n', &mut line)?;
    if line.is_empty() {
        bail!("connection closed before the response was complete");
    }
    while matches!(line.last(), Some(b'\n' | b'\r')) {
        line.pop();
    }
    Ok(String::from_utf8_lossy(&line).into_owned())
}

/// Reads `len` bytes, or to the end of the stream when `len` is `None`, never more than `max` in total.
fn read_body<R: Read>(reader: &mut R, len: Option<usize>, max: usize, out: &mut Vec<u8>) -> Result<()> {
    let limit = |len: usize, n: usize| if len + n > max { Err(anyhow!("response over {max} bytes")) } else { Ok(()) };
    match len {
        Some(n) => {
            limit(out.len(), n)?;
            let start = out.len();
            out.resize(start + n, 0);
            reader.read_exact(&mut out[start..]).context("connection closed before the body was complete")?;
        }
        None => {
            let mut buf = [0u8; 16 * 1024];
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                limit(out.len(), n)?;
                out.extend_from_slice(&buf[..n]);
            }
        }
    }
    Ok(())
}

/// One HTTP/1.1 request and its response on an open stream (`Connection: close`). The body is
/// framed by `Content-Length`, chunked encoding, or the end of the stream. `host` is the `Host`
/// header; a `Content-Length` header is added for a body unless `headers` has one.
pub fn raw_request<S: Read + Write>(
    stream: &mut S,
    method: &str,
    host: &str,
    path: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    max_body: usize,
) -> Result<Response> {
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (key, value) in headers {
        head.push_str(&format!("{key}: {value}\r\n"));
    }
    if let Some(body) = body
        && !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length"))
    {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    if let Some(body) = body {
        stream.write_all(body)?;
    }
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    // Skip informational responses (100 Continue).
    let (status, headers) = loop {
        let status_line = read_line(&mut reader)?;
        let mut parts = status_line.splitn(3, ' ');
        let version = parts.next().unwrap_or_default();
        if !version.starts_with("HTTP/") {
            bail!("not an HTTP response: {:?}", status_line.chars().take(40).collect::<String>());
        }
        let status: u16 = parts.next().and_then(|s| s.parse().ok()).ok_or_else(|| anyhow!("bad HTTP status line {status_line:?}"))?;
        let mut headers = Vec::new();
        loop {
            let line = read_line(&mut reader)?;
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }
        if !(100..200).contains(&status) || status == 101 {
            break (status, headers);
        }
    };
    let header = |name: &str| headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());

    let mut body = Vec::new();
    if method.eq_ignore_ascii_case("HEAD") || status == 204 || status == 304 {
        // No body by definition.
    } else if header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        loop {
            let size_line = read_line(&mut reader)?;
            let size_text = size_line.split(';').next().unwrap_or_default().trim();
            let size = usize::from_str_radix(size_text, 16).map_err(|_| anyhow!("bad chunk size {size_text:?}"))?;
            if size == 0 {
                // Trailers, up to the blank line (or the end of the stream).
                while read_line(&mut reader).is_ok_and(|l| !l.is_empty()) {}
                break;
            }
            read_body(&mut reader, Some(size), max_body, &mut body)?;
            read_line(&mut reader)?; // the CRLF after the chunk
        }
    } else if let Some(length) = header("content-length") {
        let n: usize = length.trim().parse().map_err(|_| anyhow!("bad Content-Length {length:?}"))?;
        read_body(&mut reader, Some(n), max_body, &mut body)?;
    } else {
        read_body(&mut reader, None, max_body, &mut body)?;
    }
    Ok(Response { status, headers, body })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A stream that reads a canned response and records what was written.
    struct Fake {
        input: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl Read for Fake {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for Fake {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn exchange(response: &str, method: &str, body: Option<&[u8]>, max: usize) -> (Result<Response>, String) {
        let mut stream = Fake { input: Cursor::new(response.as_bytes().to_vec()), written: Vec::new() };
        let result = raw_request(&mut stream, method, "docker", "/containers/json", &[("Accept".into(), "application/json".into())], body, max);
        (result, String::from_utf8_lossy(&stream.written).into_owned())
    }

    #[test]
    fn raw_request_decodes_chunked_bodies_with_extensions_and_trailers() {
        let wire = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\n[{\"a\"\r\n7\r\n:\"b\"}]\n\r\n0\r\nX-Trailer: 1\r\n\r\n";
        let (response, written) = exchange(wire, "GET", None, 1024);
        let response = response.expect("parses");
        assert_eq!(response.status, 200);
        assert_eq!(response.text(), "[{\"a\":\"b\"}]\n");
        assert_eq!(response.header("Content-Type"), Some("application/json"));
        assert!(written.starts_with("GET /containers/json HTTP/1.1\r\nHost: docker\r\nConnection: close\r\nAccept: application/json\r\n\r\n"));
    }

    #[test]
    fn raw_request_frames_by_length_or_end_of_stream_and_sends_a_body() {
        let (response, written) = exchange("HTTP/1.1 201 Created\r\nContent-Length: 4\r\n\r\nabcdEXTRA", "POST", Some(b"{}"), 1024);
        let response = response.expect("parses");
        assert_eq!((response.status, response.text().as_str()), (201, "abcd"));
        assert!(written.contains("Content-Length: 2\r\n\r\n{}"));
        let (response, _) = exchange("HTTP/1.0 404 Not Found\r\n\r\nno such container", "GET", None, 1024);
        let response = response.expect("parses");
        assert_eq!((response.status, response.ok(), response.text().as_str()), (404, false, "no such container"));
        let (response, _) = exchange("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", "GET", None, 1024);
        assert_eq!(response.expect("parses").text(), "ok");
    }

    #[test]
    fn raw_request_enforces_the_body_cap_and_rejects_truncation() {
        let (response, _) = exchange("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789", "GET", None, 5);
        assert!(response.err().expect("over the cap").to_string().contains("over 5 bytes"));
        let (response, _) = exchange("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n", "GET", None, 4);
        assert!(response.is_err());
        let (response, _) = exchange("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort", "GET", None, 1024);
        assert!(response.is_err());
    }

    #[test]
    fn closures_are_fetchers() {
        let fetch = |req: Request| -> Result<Response> { Ok(Response { status: 304, headers: vec![], body: req.url.into_bytes() }) };
        let response = Fetch::fetch(&fetch, Request::get("https://example.com/")).expect("fetches");
        assert_eq!((response.status, response.ok(), response.text().as_str()), (304, false, "https://example.com/"));
    }
}
