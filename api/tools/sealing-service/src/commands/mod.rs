// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Command dispatch.
//!
//! Routes each parsed command to the matching handler, wrapping execution in
//! the single-file workspace container lifecycle (unpack → run → pack).

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
use crate::container;
use crate::error::Error;
use crate::error::Result;
use crate::workspace::Workspace;

/// Route a parsed CLI invocation to its handler.
///
/// The workspace is a single-file container (see [`crate::container`]): the
/// state file is unpacked into a private scratch directory, the handler runs
/// against that directory exactly as it would a plain working directory, and
/// on success the scratch directory is packed back over the state file with an
/// atomic, owner-only write. On failure the state file is left untouched, so
/// every command is all-or-nothing.
pub fn dispatch(cli: Cli) -> Result<()> {
    let state_path = container::resolve_state_path();
    let scratch = container::Scratch::new()?;

    if state_path.exists() {
        let image =
            std::fs::read(&state_path).map_err(|source| Error::io("read", &state_path, source))?;
        container::unpack(&image, scratch.dir())?;
    }

    let workspace = Workspace::new(scratch.dir().to_path_buf());
    let result = run_command(&cli.command, &workspace);

    if result.is_ok() {
        let image = container::pack(scratch.dir())?;
        crate::util::write_secret(&state_path, &image)?;
    }
    result
}

/// Dispatch to the matching command handler against a resolved [`Workspace`].
fn run_command(command: &Command, workspace: &Workspace) -> Result<()> {
    match command {
        Command::CreatePartition(args) => create_partition::run(workspace, args),
        Command::CreateSdSealingKey(args) => create_sd_sealing_key::run(workspace, args),
        Command::KeyReport(args) => key_report::run(workspace, args),
        Command::CreateSd(args) => create_sd::run(workspace, args),
        Command::RestoreLocalBackup(args) => restore_local_backup::run(workspace, args),
        Command::RestoreRemoteBackup(args) => restore_remote_backup::run(workspace, args),
        Command::ResealRemoteBackup(args) => reseal_remote_backup::run(workspace, args),
        Command::CreatePeerBackup(args) => create_peer_backup::run(workspace, args),
        Command::RestorePeerBackup(args) => restore_peer_backup::run(workspace, args),
        Command::ShowPartitions => show_partitions::run(workspace),
        Command::ShowSecureDomains => show_secure_domains::run(workspace),
    }
}
