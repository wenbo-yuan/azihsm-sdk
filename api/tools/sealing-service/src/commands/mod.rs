// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Command dispatch.
//!
//! Routes each parsed command, enforces the global `--working-dir`
//! requirement, and invokes the matching handler.

mod create_partition;
mod create_peer_backup;
mod create_sd;
mod create_sd_sealing_key;
mod key_report;
mod reseal_remote_backup;
mod restore_local_backup;
mod restore_peer_backup;
mod restore_remote_backup;
mod show_partitions;
mod show_secure_domains;

use crate::cli::Cli;
use crate::cli::Command;
use crate::error::Error;
use crate::error::Result;
use crate::workspace::Workspace;

/// Route a parsed CLI invocation to its handler.
pub fn dispatch(cli: Cli) -> Result<()> {
    let name = command_name(&cli.command);
    let workspace = require_workspace(cli.working_dir, name)?;

    match &cli.command {
        Command::CreatePartition(args) => create_partition::run(&workspace, args),
        Command::CreateSdSealingKey(args) => create_sd_sealing_key::run(&workspace, args),
        Command::KeyReport(args) => key_report::run(&workspace, args),
        Command::CreateSd(args) => create_sd::run(&workspace, args),
        Command::RestoreLocalBackup(args) => restore_local_backup::run(&workspace, args),
        Command::RestoreRemoteBackup(args) => restore_remote_backup::run(&workspace, args),
        Command::ResealRemoteBackup(args) => reseal_remote_backup::run(&workspace, args),
        Command::CreatePeerBackup(args) => create_peer_backup::run(&workspace, args),
        Command::RestorePeerBackup(args) => restore_peer_backup::run(&workspace, args),
        Command::ShowPartitions => show_partitions::run(&workspace),
        Command::ShowSecureDomains => show_secure_domains::run(&workspace),
    }
}

/// The user-facing snake_case name of a command, for error and help text.
fn command_name(command: &Command) -> &'static str {
    match command {
        Command::CreatePartition(_) => "create_partition",
        Command::CreateSdSealingKey(_) => "create_sd_sealing_key",
        Command::KeyReport(_) => "key_report",
        Command::CreateSd(_) => "create_sd",
        Command::RestoreLocalBackup(_) => "restore_local_backup",
        Command::RestoreRemoteBackup(_) => "restore_remote_backup",
        Command::ResealRemoteBackup(_) => "reseal_remote_backup",
        Command::CreatePeerBackup(_) => "create_peer_backup",
        Command::RestorePeerBackup(_) => "restore_peer_backup",
        Command::ShowPartitions => "show_partitions",
        Command::ShowSecureDomains => "show_secure_domains",
    }
}

/// Resolve the global `--working-dir` into a [`Workspace`], or fail.
fn require_workspace(
    working_dir: Option<std::path::PathBuf>,
    command: &'static str,
) -> Result<Workspace> {
    working_dir
        .map(Workspace::new)
        .ok_or(Error::MissingWorkingDir(command))
}
