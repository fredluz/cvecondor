// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! cvecondor: watches public vulnerability feeds and vendor incidents against
//! what you run, and hands each likely hit to your own agent CLI.

pub mod cli;
pub mod config;
pub mod cvelist;
pub mod feeds;
pub mod fixes;
pub mod follow;
pub mod http;
pub mod inbox;
pub mod inventory;
pub mod manifests;
pub mod matching;
pub mod name;
pub mod notify;
pub mod relay;
pub mod retry;
pub mod responder;
pub mod secrets;
pub mod state;
pub mod types;
pub mod util;
pub mod upstream;
pub mod vendors;
pub mod versions;
pub mod watch;
