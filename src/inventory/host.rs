// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! The Linux machine the watcher runs on, or the host's `/` mounted read-only
//! into the watcher's container. Reads files only (os-release, the dpkg/apk
//! database, /proc/sys/kernel/osrelease) so a mounted root works the same; binaries are run for
//! `--version` only when root is `/`, because a mounted root's binaries would
//! run with this container's libraries and privileges. Compose and env files in
//! the usual project places are secret-scanned with gitleaks.

use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{Result, bail};
use indexmap::{IndexMap, IndexSet};
use regex::Regex;

use super::CollectContext;
use super::system::{
    Base, TextSource, apk_items, dedupe, dedupe_signals, dpkg_status_items, file_signals, host_file_risk, os_item, osv_ecosystem, scan_file, scan_secrets,
    version_of,
};
use crate::config::HostCollector;
use crate::secrets::Exposure;
use crate::types::{Collected, InventoryItem, ItemKind, VendorSignal};
use crate::util::{self, RunOptions};

/// Largest file read from the host.
pub const MAX_FILE: usize = 1_000_000;

/// Binaries versioned on a live root, with the flag that prints their version.
pub const HOST_BINARIES: &[(&str, &[&str])] = &[
    ("node", &["--version"]),
    ("bun", &["--version"]),
    ("deno", &["--version"]),
    ("php", &["--version"]),
    ("python3", &["--version"]),
    ("nginx", &["-v"]),
    ("apache2", &["-v"]),
    ("httpd", &["-v"]),
    ("docker", &["--version"]),
    ("containerd", &["--version"]),
    ("runc", &["--version"]),
    ("cloudflared", &["--version"]),
    ("caddy", &["version"]),
    ("traefik", &["version"]),
];

/// Binary name → the runtime name it is listed under.
pub fn runtime_name(binary: &str) -> &str {
    match binary {
        "python3" => "python",
        "apache2" => "httpd",
        other => other,
    }
}

/// `path.basename`: the last segment, trailing slashes ignored.
pub fn basename(path: &str) -> &str {
    path.trim_end_matches('/').rsplit('/').next().unwrap_or_default()
}

/// Lexical normalisation as `path.resolve` / `path.join` do it: relative paths start at the
/// working directory, `.` and empty segments go away, `..` pops (and stops at the root).
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::from("/");
    let absolute = if path.is_absolute() { path.to_path_buf() } else { std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")).join(path) };
    for component in absolute.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::ParentDir => {
                out.pop();
            }
            _ => {}
        }
    }
    out
}

/// `os.release()`: the kernel's release string, from `uname`.
fn kernel_release() -> Option<String> {
    // SAFETY: `uname` fills the zeroed struct it is given.
    let mut info: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut info) } != 0 {
        return None;
    }
    // SAFETY: on success `release` is a NUL-terminated C string.
    let release = unsafe { std::ffi::CStr::from_ptr(info.release.as_ptr()) };
    Some(release.to_string_lossy().into_owned())
}

/// Everything a binary prints, stdout then stderr (nginx and apache print their version on stderr);
/// nothing when it cannot be run.
fn version_probe(path: &str, args: &[&str]) -> String {
    let argv: Vec<String> = std::iter::once(path).chain(args.iter().copied()).map(str::to_string).collect();
    let opts = RunOptions { timeout: Some(Duration::from_secs(5)), max_output: 1 << 20, ..RunOptions::default() };
    match util::run(&argv, &opts) {
        Ok(out) => format!("{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)),
        Err(_) => "\n".to_string(),
    }
}

/// The first regular file called `name` in PATH (or the usual system dirs); a name with a `/` is used as given.
fn which(name: &str) -> Option<String> {
    if name.contains('/') {
        return Path::new(name).exists().then(|| name.to_string());
    }
    let path = std::env::var("PATH").unwrap_or_default();
    let dirs = path.split(':').chain(["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"]);
    dirs.filter(|d| !d.is_empty())
        .map(|dir| Path::new(dir).join(name))
        .find(|p| std::fs::metadata(p).is_ok_and(|m| m.is_file()))
        .map(|p| p.to_string_lossy().into_owned())
}

/// Project dirs and env files where compose files, `.env`s and systemd environments sit, as host paths.
fn scan_targets(read: &dyn Fn(&str) -> String, list: &dyn Fn(&str) -> Vec<String>) -> (Vec<String>, Vec<String>) {
    static WORKING_DIR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^WorkingDirectory=-?(/\S+)").expect("valid regex"));
    static ENV_FILE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^EnvironmentFile=-?(/\S+)").expect("valid regex"));
    let mut dirs: IndexSet<String> = IndexSet::new();
    let mut env_files: IndexSet<String> = IndexSet::new();
    for unit in list("/etc/systemd/system").iter().filter(|f| f.ends_with(".service")) {
        let text = read(&format!("/etc/systemd/system/{unit}"));
        dirs.extend(WORKING_DIR.captures_iter(&text).map(|m| m[1].to_string()));
        env_files.extend(ENV_FILE.captures_iter(&text).map(|m| m[1].to_string()));
    }
    for top in ["/opt", "/srv", "/root"] {
        dirs.extend(list(top).into_iter().map(|d| format!("{top}/{d}")));
    }
    for user in list("/home") {
        dirs.extend(list(&format!("/home/{user}")).into_iter().map(|d| format!("/home/{user}/{d}")));
    }
    (dirs.into_iter().collect(), env_files.into_iter().collect())
}

pub fn collect_host(config: &HostCollector, context: &CollectContext) -> Result<Collected> {
    let host = config.name.as_str();
    let root = normalize(&config.root);
    let live = root == Path::new("/");
    let under = |path: &str| normalize(&root.join(path.trim_start_matches('/')));
    let read = |path: &str| -> String { std::fs::read(under(path)).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default() };
    // The directory's entries in name order, as Node lists them.
    let list = |path: &str| -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(under(path)) else { return Vec::new() };
        let mut names: Vec<String> = entries.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        names
    };
    let os_release = Some(read("/etc/os-release")).filter(|t| !t.is_empty()).unwrap_or_else(|| read("/usr/lib/os-release"));
    if os_release.is_empty() && !under("/proc").exists() && !under("/etc").exists() {
        bail!("{} does not look like a Linux root", root.display());
    }
    let base = Base::new(host, "host");
    let mut warnings: Vec<String> = Vec::new();
    let mut items: Vec<InventoryItem> = os_item(&os_release, base);
    let kernel = read("/proc/sys/kernel/osrelease");
    let kernel = util::js_trim(&kernel);
    let kernel = if !kernel.is_empty() {
        kernel.to_string()
    } else if live {
        kernel_release().unwrap_or_default()
    } else {
        "unknown".to_string()
    };
    items.push(InventoryItem {
        host: host.to_string(),
        r#where: "host".to_string(),
        kind: ItemKind::Os,
        ecosystem: None,
        name: "linux kernel".to_string(),
        version: kernel,
        path: None,
        running: None,
        dev: None,
        collector: None,
    });
    let eco = osv_ecosystem(&os_release);
    let pkg_base = Base { ecosystem: eco.as_deref(), ..base };
    let dpkg = read("/var/lib/dpkg/status");
    items.extend(if dpkg.is_empty() { apk_items(&read("/lib/apk/db/installed"), pkg_base) } else { dpkg_status_items(&dpkg, pkg_base) });
    if live {
        // The built-in list, then the configured extras; a configured name already in the list keeps its place and gets `--version`.
        let mut probes: IndexMap<&str, Vec<&str>> = HOST_BINARIES.iter().map(|(b, args)| (*b, args.to_vec())).collect();
        for binary in &config.binaries {
            probes.insert(binary.as_str(), vec!["--version"]);
        }
        for (binary, args) in &probes {
            let Some(path) = which(binary) else { continue };
            let Some(version) = version_of(&version_probe(&path, args)).map(str::to_string) else { continue };
            let mut item = base.item(ItemKind::Runtime, runtime_name(basename(binary)), version);
            item.path = Some(path);
            items.push(item);
        }
    }
    let (dirs, env_files) = scan_targets(&read, &list);
    let mut files: IndexMap<String, bool> = IndexMap::new();
    for dir in &dirs {
        for name in list(dir) {
            if scan_file(&name) {
                files.insert(format!("{dir}/{name}"), false);
            }
        }
    }
    for file in env_files {
        files.insert(file, true);
    }
    let mut sources: Vec<TextSource> = Vec::new();
    let mut signals: Vec<VendorSignal> = Vec::new();
    for (path, env) in &files {
        let Ok(meta) = std::fs::metadata(under(path)) else { continue };
        if !meta.is_file() {
            continue;
        }
        if meta.len() > MAX_FILE as u64 {
            warnings.push(format!("{path}: over {MAX_FILE} bytes, not scanned"));
            continue;
        }
        let text = read(path);
        if text.is_empty() {
            continue;
        }
        signals.extend(file_signals(path, &text, host, "host", env.then_some(true)));
        sources.push(TextSource {
            r#where: "host".to_string(),
            location: path.clone(),
            text,
            exposure: Exposure::HostFile,
            risk: host_file_risk(meta.permissions().mode() & 0o004 != 0).to_string(),
            env: env.then_some(true),
        });
    }
    (context.log)(&format!("{host}: {} items, scanning {} config files for secrets", items.len(), sources.len()));
    let secrets = scan_secrets(host, &sources, &mut warnings);
    Ok(Collected { items: dedupe(items), services: Vec::new(), secrets, signals: dedupe_signals(signals), warnings })
}
