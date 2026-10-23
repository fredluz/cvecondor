// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! The inventory: every configured collector, each refreshed independently. A
//! collector that fails keeps its previous items, marked with the error, so one
//! unreachable host never blanks what the watcher matches against.

pub mod docker;
pub mod github;
pub mod host;
pub mod ssh;
pub mod system;

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;

use anyhow::{Result, anyhow};

use crate::config::{CollectorConfig, Config, redact};
use crate::http::{Fetch, Net};
use crate::types::{Collected, Inventory, SourceStatus};
use crate::util;

/// What a collector is given.
pub struct CollectContext<'a> {
    /// The watcher's state dir; a collector may keep a cache file there (`<collector name>.cache.json`).
    pub state_dir: &'a Path,
    pub fetch: &'a dyn Fetch,
    pub log: &'a (dyn Fn(&str) + Sync),
    /// The previous inventory, when there is one.
    pub previous: Option<&'a Inventory>,
}

/// Runs one collector. `collect_inventory` takes a replacement in `CollectOptions::collect` (tests).
pub type Collect = dyn for<'a, 'b> Fn(&'a CollectorConfig, &'b CollectContext<'b>) -> anyhow::Result<Collected> + Sync;

/// What `collect_inventory` can be told beyond the config. Every field is optional.
#[derive(Default)]
pub struct CollectOptions<'a> {
    /// Replaces `run_collector`.
    pub collect: Option<&'a Collect>,
    /// Replaces the real network client.
    pub fetch: Option<&'a dyn Fetch>,
    pub log: Option<&'a (dyn Fn(&str) + Sync)>,
    /// Only these collectors (by name) refresh; the others keep their previous items.
    pub only: Option<Vec<String>>,
}

/// Runs one collector.
pub fn run_collector(collector: &CollectorConfig, context: &CollectContext) -> Result<Collected> {
    match collector {
        CollectorConfig::Github(c) => github::collect_github(c, context),
        CollectorConfig::Host(c) => host::collect_host(c, context),
        CollectorConfig::Docker(c) => docker::collect_docker(c, context),
        CollectorConfig::Ssh(c) => ssh::collect_ssh(c, context),
    }
}

/// The first `max` characters of `text`.
fn truncate(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// Every collector runs at once, each on its own thread. One that fails (or panics) keeps its previous
/// items, services, secrets and signals, with its status marked `ok: false` and the error.
pub fn collect_inventory(config: &Config, previous: Option<&Inventory>, options: CollectOptions) -> Inventory {
    let at = util::iso(util::now());
    let net = Net;
    let log_nothing = |_: &str| {};
    let context = CollectContext { state_dir: &config.state_dir, fetch: options.fetch.unwrap_or(&net), log: options.log.unwrap_or(&log_nothing), previous };
    let default_collect = |collector: &CollectorConfig, context: &CollectContext| run_collector(collector, context);
    let collect: &Collect = options.collect.unwrap_or(&default_collect);
    let only = options.only.as_deref();
    let mut inventory = Inventory { collected_at: at.clone(), ..Inventory::default() };
    // `None`: not asked to run this time.
    let results: Vec<Option<Result<Collected>>> = util::parallel_map(&config.collectors, config.collectors.len(), |collector| {
        if only.is_some_and(|only| !only.iter().any(|n| n == collector.name())) {
            return None;
        }
        Some(catch_unwind(AssertUnwindSafe(|| collect(collector, &context))).unwrap_or_else(|panic| {
            let message = panic.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| panic.downcast_ref::<String>().cloned());
            Err(anyhow!(message.unwrap_or_else(|| "collector panicked".to_string())))
        }))
    });
    for (collector, result) in config.collectors.iter().zip(results) {
        let name = collector.name();
        let own = |collector: &Option<String>| collector.as_deref() == Some(name);
        // `Err(None)`: skipped this time; `Err(Some(_))`: it failed.
        let outcome = match result {
            Some(Ok(collected)) => Ok(collected),
            Some(Err(error)) => Err(Some(error)),
            None => Err(None),
        };
        let failure = match outcome {
            Ok(collected) => {
                let Collected { items, services, secrets, signals, warnings } = collected;
                let (item_count, secret_count) = (items.len(), secrets.len());
                inventory.items.extend(items.into_iter().map(|mut x| {
                    x.collector = Some(name.to_string());
                    x
                }));
                inventory.services.extend(services.into_iter().map(|mut x| {
                    x.collector = Some(name.to_string());
                    x
                }));
                inventory.secrets.extend(secrets.into_iter().map(|mut x| {
                    x.collector = Some(name.to_string());
                    x
                }));
                inventory.signals.extend(signals.into_iter().map(|mut x| {
                    x.collector = Some(name.to_string());
                    x
                }));
                inventory.sources.insert(
                    name.to_string(),
                    SourceStatus {
                        ok: true,
                        at: at.clone(),
                        items: item_count,
                        secrets: secret_count,
                        error: None,
                        warnings: (!warnings.is_empty()).then(|| warnings.iter().map(|w| truncate(&redact(config, w), 300)).collect()),
                    },
                );
                continue;
            }
            Err(failure) => failure,
        };
        let (own_items, own_secrets) = (
            previous.map(|p| p.items.iter().filter(|x| own(&x.collector)).cloned().collect::<Vec<_>>()).unwrap_or_default(),
            previous.map(|p| p.secrets.iter().filter(|x| own(&x.collector)).cloned().collect::<Vec<_>>()).unwrap_or_default(),
        );
        let (item_count, secret_count) = (own_items.len(), own_secrets.len());
        inventory.items.extend(own_items);
        inventory.secrets.extend(own_secrets);
        if let Some(p) = previous {
            inventory.services.extend(p.services.iter().filter(|x| own(&x.collector)).cloned());
            inventory.signals.extend(p.signals.iter().filter(|x| own(&x.collector)).cloned());
        }
        let before = previous.and_then(|p| p.sources.get(name));
        let status = match failure {
            // Skipped this time: what it was before, or a note that it never ran.
            None => before.cloned().unwrap_or_else(|| SourceStatus {
                ok: false,
                at: at.clone(),
                items: 0,
                secrets: 0,
                error: Some("not collected yet".to_string()),
                warnings: None,
            }),
            Some(error) => SourceStatus {
                ok: false,
                at: before.map_or_else(|| at.clone(), |b| b.at.clone()),
                items: item_count,
                secrets: secret_count,
                error: Some(truncate(&redact(config, &error.to_string()), 400)),
                warnings: None,
            },
        };
        inventory.sources.insert(name.to_string(), status);
    }
    inventory
}
