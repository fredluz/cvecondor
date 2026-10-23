// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! The tool's name, in one place for the code. Renaming it also means
//! `Cargo.toml`, the Dockerfile, action.yml and the docs: `git grep -il cvecondor`

pub const NAME: &str = "cvecondor";
pub const VERSION: &str = "0.1.0";
pub const USER_AGENT: &str = "cvecondor/0.1.0";
/// Environment variables are `<PREFIX>_CONFIG`, `<PREFIX>_STATE_DIR`:
/// `NAME` upper-cased with every character outside `A-Z0-9` turned into `_`.
pub const ENV_PREFIX: &str = "CVECONDOR";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_constants_follow_the_name() {
        assert_eq!(USER_AGENT, format!("{NAME}/{VERSION}"));
        let prefix: String = NAME.to_uppercase().chars().map(|c| if c.is_ascii_uppercase() || c.is_ascii_digit() { c } else { '_' }).collect();
        assert_eq!(ENV_PREFIX, prefix);
    }
}
