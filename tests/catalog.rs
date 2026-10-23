// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! The vendor catalogue is data other collectors trust blindly: ids must be
//! unique, feeds https, and the file/package matchers must hit the obvious cases.

use std::collections::HashSet;

use cvecondor::vendors::catalog::{VENDORS, package_vendor, vendor_file_match, vendors_for_file};

fn ids(vendors: Vec<&cvecondor::vendors::catalog::VendorDef>) -> Vec<&str> {
    vendors.into_iter().map(|v| v.id.as_str()).collect()
}

#[test]
fn vendor_ids_are_unique() {
    let ids: Vec<&str> = VENDORS.iter().map(|v| v.id.as_str()).collect();
    assert_eq!(ids.iter().collect::<HashSet<_>>().len(), ids.len());
}

#[test]
fn every_feed_url_is_https() {
    for v in VENDORS.iter() {
        for f in &v.feeds {
            assert!(f.url.starts_with("https://"), "{}: {}", v.id, f.url);
        }
    }
}

#[test]
fn vendor_file_match_recognises_vendor_config_files() {
    for path in ["vercel.json", "apps/web/vercel.json", ".vercel/project.json", "amplify/backend/x.json"] {
        assert!(vendor_file_match(path), "{path}");
    }
    assert!(!vendor_file_match("src/index.ts"));
    assert_eq!(ids(vendors_for_file("apps/web/vercel.json")), ["vercel"]);
}

#[test]
fn package_vendor_maps_npm_scopes() {
    assert_eq!(ids(package_vendor("npm", "@vercel/analytics")), ["vercel"]);
    assert_eq!(ids(package_vendor("PyPI", "google-cloud-storage")), ["gcp"]);
    assert!(package_vendor("npm", "left-pad").is_empty());
}

#[test]
fn env_prefixes_are_specific_enough() {
    for v in VENDORS.iter() {
        for e in &v.env {
            if e.ends_with('_') {
                assert!(e.len() > 3, "{}: {}", v.id, e);
            }
        }
    }
}
