// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! What repo files say a repo runs: images and their runtimes, dev flags, pins, platforms.

use cvecondor::manifests::{is_repo_file, parse_repo_file};
use serde_json::json;

fn brief(path: &str, text: &str, siblings: &[&str]) -> Vec<String> {
    let siblings: Vec<String> = siblings.iter().map(|s| s.to_string()).collect();
    parse_repo_file(path, text, &siblings)
        .iter()
        .map(|f| {
            let ecosystem = f.ecosystem.as_deref().map(|e| format!("{e} ")).unwrap_or_default();
            format!("{} {}{} {}{}", f.kind.as_str(), ecosystem, f.name, f.version, if f.dev == Some(true) { " dev" } else { "" })
        })
        .collect()
}

#[test]
fn dockerfile_arg_defaults_substitute_into_from_stage_names_and_scratch_are_skipped() {
    let dockerfile = [
        "ARG NODE_VERSION=22.21.0",
        "ARG BASE",
        "ARG DISTRO=\"bookworm\"",
        "FROM --platform=$BUILDPLATFORM node:${NODE_VERSION}-alpine AS build",
        "ARG LATE=1",
        "FROM build AS test",
        "FROM debian:${DISTRO}-slim",
        "FROM ${BASE}",
        "FROM img:$LATE",
        "FROM ghcr.io/acme/tool:${TAG:-2.0}@sha256:abc",
        "FROM scratch",
    ]
    .join("\n");
    assert_eq!(
        brief("svc/Dockerfile", &dockerfile, &[]),
        ["image node 22.21.0-alpine", "runtime node 22.21.0", "image debian bookworm-slim", "os Debian:12 Debian 12", "image tool 2.0"]
    );
}

#[test]
fn image_tags_a_php_x_y_inside_any_tag_official_runtimes_only() {
    let compose = "services:\n  wp:\n    image: \"wordpress:6.8.3-php8.3-apache\"\n  db:\n    image: mariadb:11\n  app:\n    image: php:8.3-apache\n  x:\n    image: someone/node:20\n  u:\n    image: ubuntu\n  y:\n    image: ${IMAGE}\n";
    assert_eq!(
        brief("docker-compose.prod.yml", compose, &[]),
        [
            "image wordpress 6.8.3-php8.3-apache",
            "runtime php 8.3",
            "image mariadb 11",
            "image php 8.3-apache",
            "image node 20",
            "image ubuntu latest",
            "os Ubuntu latest"
        ]
    );
}

#[test]
fn dev_flags_from_lockfiles() {
    let lock = json!({ "packages": { "": {}, "node_modules/a": { "version": "1.0.0" }, "node_modules/b": { "version": "2.0.0", "dev": true }, "node_modules/c": { "version": "3.0.0", "devOptional": true } } }).to_string();
    assert_eq!(brief("package-lock.json", &lock, &[]), ["package npm a 1.0.0", "package npm b 2.0.0 dev", "package npm c 3.0.0 dev"]);
    let composer = json!({ "packages": [{ "name": "x/a", "version": "v1.2.0" }], "packages-dev": [{ "name": "x/b", "version": "3.0.0" }] }).to_string();
    assert_eq!(brief("composer.lock", &composer, &[]), ["package Packagist x/a 1.2.0", "package Packagist x/b 3.0.0 dev"]);
    let poetry =
        "[[package]]\nname = \"flask\"\nversion = \"3.0.0\"\ncategory = \"main\"\n\n[[package]]\nname = \"pytest\"\nversion = \"8.0.0\"\ncategory = \"dev\"\n";
    assert_eq!(brief("poetry.lock", poetry, &[]), ["package PyPI flask 3.0.0", "package PyPI pytest 8.0.0 dev"]);
}

#[test]
fn package_json_and_pyproject_pins_count_only_without_a_lockfile_beside_them() {
    let pkg = json!({ "engines": { "node": "22.0.0" }, "dependencies": { "a": "1.2.3", "b": "^1.2.3", "c": "~1.0.0" }, "devDependencies": { "d": "4.5.6" } })
        .to_string();
    assert_eq!(brief("web/package.json", &pkg, &["web/src/index.ts", "yarn.lock"]), ["package npm a 1.2.3", "package npm d 4.5.6 dev"]);
    assert!(brief("web/package.json", &pkg, &["web/package.json", "web/yarn.lock"]).is_empty());
    let pyproject = "[project]\ndependencies = [\"requests==2.32.3\", \"flask>=3\"]\n[dependency-groups]\ndev = [\"pytest==8.3.0\"]\n";
    assert_eq!(brief("pyproject.toml", pyproject, &[]), ["package PyPI requests 2.32.3", "package PyPI pytest 8.3.0 dev"]);
    assert!(brief("pyproject.toml", pyproject, &["uv.lock"]).is_empty());
}

#[test]
fn go_mod_and_gemfile_lock_give_packages_and_the_runtime() {
    let gomod = "module x\n\ngo 1.22.0\n\ntoolchain go1.22.5\n\nrequire github.com/a/b v1.2.3\n\nrequire (\n\tgolang.org/x/net v0.30.0 // indirect\n\tgithub.com/c/d v0.0.0-20240101000000-abcdef123456\n)\n";
    assert_eq!(
        brief("go.mod", gomod, &[]),
        [
            "package Go github.com/a/b 1.2.3",
            "package Go golang.org/x/net 0.30.0",
            "package Go github.com/c/d 0.0.0-20240101000000-abcdef123456",
            "runtime go 1.22.5"
        ]
    );
    assert!(brief("go.sum", "github.com/a/b v1.2.3 h1:x=\n", &["go.mod"]).is_empty());
    let gemfile = "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.16.0-x86_64-linux)\n      racc (~> 1.4)\n    rack (3.0.8)\n\nPLATFORMS\n  x86_64-linux\n\nRUBY VERSION\n   ruby 3.3.0p0\n";
    assert_eq!(brief("Gemfile.lock", gemfile, &[]), ["package RubyGems nokogiri 1.16.0", "package RubyGems rack 3.0.8", "runtime ruby 3.3.0"]);
}

#[test]
fn platform_markers_and_version_files() {
    assert_eq!(brief("fly.toml", "", &[]), ["platform fly -"]);
    assert_eq!(brief("supabase/config.toml", "", &[]), ["platform supabase -"]);
    assert_eq!(brief("app.json", "{}", &["app.json", "Procfile"]), ["platform heroku -"]);
    assert!(brief("app.json", "{}", &["app.json"]).is_empty());
    assert_eq!(brief(".nvmrc", "v22.21.0\n", &[]), ["runtime node 22.21.0"]);
    assert!(brief(".nvmrc", "lts/*\n", &[]).is_empty());
    assert_eq!(brief(".tool-versions", "nodejs 20.11.0\ngolang 1.23.1\nterraform 1.9.0\n", &[]), ["runtime node 20.11.0", "runtime go 1.23.1"]);
    assert!(!is_repo_file("node_modules/x/package.json"));
    assert!(is_repo_file("deploy/api.Dockerfile"));
}

#[test]
fn npm_lockfile_v3_entries_with_dependency_maps_still_read_and_a_wrongly_typed_one_is_skipped() {
    let lock = json!({
        "lockfileVersion": 3,
        "packages": {
            "": { "name": "app", "dependencies": { "a": "^1.0.0" }, "devDependencies": { "b": "^2.0.0" } },
            "node_modules/a": { "version": "1.0.0", "dependencies": { "c": "^3.0.0" } },
            "node_modules/b": { "version": "2.0.0", "dev": true, "devDependencies": { "c": "^3.0.0" } },
            "node_modules/c": { "version": "3.0.0", "optionalDependencies": { "d": "^4.0.0" } },
            "node_modules/bad": 5,
            "node_modules/odd": { "version": 3, "dev": "yes" },
            "node_modules/d": { "version": "4.0.0", "dev": "yes", "optional": true }
        }
    })
    .to_string();
    assert_eq!(brief("package-lock.json", &lock, &[]), ["package npm a 1.0.0", "package npm b 2.0.0 dev", "package npm c 3.0.0", "package npm d 4.0.0 dev"]);
}

#[test]
fn a_bom_at_the_start_of_requirements_txt_keeps_its_first_package() {
    assert_eq!(brief("requirements.txt", "\u{feff}flask==3.0.0\nrequests==2.31.0\n", &[]), ["package PyPI flask 3.0.0", "package PyPI requests 2.31.0"]);
}
