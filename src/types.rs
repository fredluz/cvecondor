// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! The inventory: what the collectors saw. These are the shapes of `inventory.json`
//! and of what a collector returns.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::secrets::SecretFinding;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ItemKind {
    Os,
    OsPackage,
    Runtime,
    Image,
    Package,
    Platform,
}

impl ItemKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Os => "os",
            Self::OsPackage => "os-package",
            Self::Runtime => "runtime",
            Self::Image => "image",
            Self::Package => "package",
            Self::Platform => "platform",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryItem {
    /// The machine or account it belongs to: the collector's name (`github`, `web1`, …).
    pub host: String,
    /// `host`, `container:<name>`, `service:<unit>`, `repo:<owner>/<name>`
    pub r#where: String,
    /// `image`: a container image reference (name = repository basename, version = tag), from a Dockerfile, compose file or running container.
    /// `platform`: where a repo deploys (`railway`, `vercel`, `fly`, …, from its config files; version `-`), so a platform incident finds it.
    pub kind: ItemKind,
    /// OSV ecosystem for package lookups (`Ubuntu:24.04:LTS`, `Debian:13`, `Alpine:v3.22`, `npm`, `PyPI`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<String>,
    pub name: String,
    pub version: String,
    /// The file it came from (repo-relative for GitHub) or the binary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// false: a stopped container. Absent: not applicable (repos) or unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub running: Option<bool>,
    /// Only a development dependency (when the lockfile says so).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<bool>,
    /// The collector that produced it; set by `collect_inventory`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceInfo {
    pub host: String,
    /// Same `where` as its items: `host`, `container:<name>`, `service:<unit>`.
    pub r#where: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart: Option<String>,
    /// Public hostnames (VIRTUAL_HOST, Traefik Host rules) and non-loopback ports. Empty: not reachable from outside as far as the host shows.
    #[serde(default)]
    pub exposed: Vec<String>,
    /// Compose project directory, for the responder's restore commands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceStatus {
    pub ok: bool,
    pub at: String,
    pub items: usize,
    pub secrets: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VendorSignalKind {
    /// A variable's name: container env, `.env.example`, compose `environment:`, workflow `secrets.X`, Actions secret names.
    Env,
    /// A repo path matching a catalogue file pattern.
    File,
    /// A GitHub deployment's creator login or environment name.
    Deployment,
    /// A service domain seen in config (`*.supabase.co`).
    Hostname,
}

/// Evidence of which vendors a place uses, beyond its packages and images
/// (those are items already). Names only: an env signal is a variable's name, never its value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VendorSignal {
    pub host: String,
    pub r#where: String,
    pub kind: VendorSignalKind,
    pub value: String,
    /// Where it was seen (a file path, `env`, `deployments`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Inventory {
    pub collected_at: String,
    /// Per collector name.
    #[serde(default)]
    pub sources: IndexMap<String, SourceStatus>,
    #[serde(default)]
    pub items: Vec<InventoryItem>,
    #[serde(default)]
    pub services: Vec<ServiceInfo>,
    #[serde(default)]
    pub secrets: Vec<SecretFinding>,
    #[serde(default)]
    pub signals: Vec<VendorSignal>,
}

#[derive(Debug, Clone, Default)]
pub struct Collected {
    pub items: Vec<InventoryItem>,
    pub services: Vec<ServiceInfo>,
    pub secrets: Vec<SecretFinding>,
    pub signals: Vec<VendorSignal>,
    /// Partial failures that keep the rest (gitleaks missing, a repo that could not be cloned, a file over the size cap).
    pub warnings: Vec<String>,
}
