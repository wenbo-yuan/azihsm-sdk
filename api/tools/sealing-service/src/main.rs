// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `azihsm-sealing-service` — command-line tool for sealing-service
//! secure-domain provisioning, backup, restore, reseal, peer-backup, and
//! inspection flows.
//!
//! See `api/docs/design-sealing-service-cli.md` for the full design. This
//! binary is the scaffold: the command surface, flavor identity, and workspace
//! model are wired, and each command handler is a stub pending implementation.
//!
//! Both flavors build this same binary and differ only by a compile-time Cargo
//! feature. The `emu` flavor is built with `--features emu`; the `hw` flavor is
//! the default. The active flavor is reported by `--version`.

// The scaffold defines the manifest and workspace types the command handlers
// will consume once implemented; their fields are intentionally not yet read.
#![allow(dead_code)]

mod authority;
mod cli;
mod commands;
mod container;
mod crypto;
mod error;
mod evidence;
mod flavor;
mod manifest;
mod provision;
mod reconstruct;
mod util;
mod workspace;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::Cli;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match commands::dispatch(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
