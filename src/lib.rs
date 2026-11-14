// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! cvecondor: watches public vulnerability feeds and vendor incidents against
//! what you run, and hands each likely hit to your own agent CLI.

pub mod cli;
pub mod config;
pub mod cvelist;
pub mod dashboard;
pub mod feeds;
pub mod fixes;
pub mod follow;
pub mod http;
pub mod inbox;
pub mod inventory;
pub mod judged;
pub mod manifests;
pub mod matching;
pub mod name;
pub mod notify;
pub mod relay;
pub mod responder;
pub mod retry;
pub mod secrets;
pub mod service;
pub mod state;
pub mod telegram;
pub mod types;
pub mod upstream;
pub mod util;
pub mod vendors;
pub mod versions;
pub mod visibility;
pub mod watch;
