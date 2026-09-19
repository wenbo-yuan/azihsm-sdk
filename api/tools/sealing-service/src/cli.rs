// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Command-line surface for `azihsm-sealing-service`.
//!
//! The argument definitions mirror the command-contracts table in
//! `api/docs/design-sealing-service-cli.md`. All host-side state lives in a
//! single-file workspace container selected by the `AZIHSM_SEALING_STATE_PATH`
//! environment variable (see [`crate::container`]); there is no per-command
//! working-directory option.

use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;

/// `azihsm-sealing-service` — sealing-service secure-domain CLI.
#[derive(Debug, Parser)]
#[command(
    name = "azihsm-sealing-service",
    version = crate::flavor::VERSION,
    about = "Sealing-service secure-domain provisioning, backup, and inspection CLI",
    long_about = None,
)]
pub struct Cli {
    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Every user-facing command. Names are SDK-style snake_case so each maps
/// clearly to one sealing-service operation.
#[derive(Debug, Subcommand)]
#[command(rename_all = "snake_case")]
pub enum Command {
    /// Initialize a partition workspace and its attestation artifacts.
    CreatePartition(CreatePartitionArgs),

    /// Generate a named SD sealing key on a partition.
    CreateSdSealingKey(CreateSdSealingKeyArgs),

    /// Produce an attestation evidence bundle for a sealing key.
    KeyReport(KeyReportArgs),

    /// Create a secure domain and its first backups.
    CreateRemoteBackup(CreateRemoteBackupArgs),

    /// Refresh the operating partition's own device-local recovery point.
    RestoreLocalBackup(RestoreLocalBackupArgs),

    /// Join a secure domain from a remote hand-off addressed to this partition.
    RestoreRemoteBackup(RestoreRemoteBackupArgs),

    /// Re-wrap a domain's BKS3 to a new destination partition.
    ResealRemoteBackup(ResealRemoteBackupArgs),

    /// Produce a peer hand-off backup for another partition in the domain.
    CreatePeerBackup(CreatePeerBackupArgs),

    /// Join a secure domain from a peer hand-off addressed to this partition.
    RestorePeerBackup(RestorePeerBackupArgs),

    /// Print a per-partition inventory table.
    ShowPartitions,

    /// Print per-secure-domain membership and hand-off lineage.
    ShowSecureDomains,
}

/// `create_partition` arguments.
#[derive(Debug, clap::Args)]
pub struct CreatePartitionArgs {
    /// Logical partition workspace name.
    #[arg(long, value_name = "NAME")]
    pub partition: String,

    /// Create a new authority set (and its backing policy) with this name.
    /// Mutually exclusive with `--authority-set`.
    #[arg(long, value_name = "NAME", conflicts_with_all = ["authority_set"])]
    pub new_authority_set: Option<String>,

    /// Reuse an existing authority set with this name. Its single stored shared
    /// policy is loaded from the workspace container.
    #[arg(long, value_name = "NAME")]
    pub authority_set: Option<String>,
}

/// `create_sd_sealing_key` arguments.
#[derive(Debug, clap::Args)]
pub struct CreateSdSealingKeyArgs {
    /// Partition that owns the new sealing key.
    #[arg(long, value_name = "NAME")]
    pub partition: String,

    /// Name for the new sealing key.
    #[arg(long, value_name = "NAME")]
    pub sealing_key: String,
}

/// `key_report` arguments.
#[derive(Debug, clap::Args)]
pub struct KeyReportArgs {
    /// Partition that owns the sealing key.
    #[arg(long, value_name = "NAME")]
    pub partition: String,

    /// Sealing key to attest.
    #[arg(long, value_name = "NAME")]
    pub sealing_key: String,

    /// Name for the generated evidence bundle.
    #[arg(long, value_name = "NAME")]
    pub report: String,

    /// Optional report-data file bound into the key report.
    #[arg(long, value_name = "FILE")]
    pub report_data: Option<PathBuf>,
}

/// `create_remote_backup` arguments.
#[derive(Debug, clap::Args)]
pub struct CreateRemoteBackupArgs {
    /// Backing partition that creates the domain.
    #[arg(long, value_name = "NAME")]
    pub partition: String,

    /// Name for the new secure domain.
    #[arg(long, value_name = "NAME")]
    pub secure_domain: String,

    /// Backing partition's sealing key.
    #[arg(long, value_name = "NAME")]
    pub sealing_key: String,

    /// Receiver evidence workspace reference `<partition>/<key>/<report>`.
    #[arg(long, value_name = "REF")]
    pub receiver_evidence: String,
}

/// `restore_local_backup` arguments.
#[derive(Debug, clap::Args)]
pub struct RestoreLocalBackupArgs {
    /// Member partition refreshing its own recovery point.
    #[arg(long, value_name = "NAME")]
    pub partition: String,

    /// Secure domain to refresh.
    #[arg(long, value_name = "NAME")]
    pub secure_domain: String,
}

/// `restore_remote_backup` arguments.
#[derive(Debug, clap::Args)]
pub struct RestoreRemoteBackupArgs {
    /// Receiver partition joining the domain.
    #[arg(long, value_name = "NAME")]
    pub partition: String,

    /// Secure domain to join.
    #[arg(long, value_name = "NAME")]
    pub secure_domain: String,

    /// Receiver's own sealing key.
    #[arg(long, value_name = "NAME")]
    pub sealing_key: String,

    /// Sender evidence workspace reference `<partition>/<key>/<report>`.
    #[arg(long, value_name = "REF")]
    pub sender_evidence: String,
}

/// `reseal_remote_backup` arguments.
#[derive(Debug, clap::Args)]
pub struct ResealRemoteBackupArgs {
    /// Member partition that holds the domain and reseals its backup.
    #[arg(long, value_name = "NAME")]
    pub partition: String,

    /// Secure domain whose backup is resealed.
    #[arg(long, value_name = "NAME")]
    pub secure_domain: String,

    /// Reseal partition's own sealing key (opens the source backup).
    #[arg(long, value_name = "NAME")]
    pub sealing_key: String,

    /// Source evidence workspace reference `<partition>/<key>/<report>`.
    #[arg(long, value_name = "REF")]
    pub sender_evidence: String,

    /// New destination evidence workspace reference `<partition>/<key>/<report>`.
    #[arg(long, value_name = "REF")]
    pub receiver_evidence: String,
}

/// `create_peer_backup` arguments.
#[derive(Debug, clap::Args)]
pub struct CreatePeerBackupArgs {
    /// Member partition producing the peer hand-off.
    #[arg(long, value_name = "NAME")]
    pub partition: String,

    /// Secure domain the peer will join.
    #[arg(long, value_name = "NAME")]
    pub secure_domain: String,

    /// Operating partition's own sealing key.
    #[arg(long, value_name = "NAME")]
    pub sealing_key: String,

    /// Destination peer evidence workspace reference `<partition>/<key>/<report>`.
    #[arg(long, value_name = "REF")]
    pub peer_evidence: String,
}

/// `restore_peer_backup` arguments.
#[derive(Debug, clap::Args)]
pub struct RestorePeerBackupArgs {
    /// Receiving peer partition joining the domain.
    #[arg(long, value_name = "NAME")]
    pub partition: String,

    /// Secure domain to join.
    #[arg(long, value_name = "NAME")]
    pub secure_domain: String,

    /// Receiving peer's own sealing key.
    #[arg(long, value_name = "NAME")]
    pub sealing_key: String,

    /// Source-peer evidence workspace reference `<partition>/<key>/<report>`.
    #[arg(long, value_name = "REF")]
    pub peer_evidence: String,
}
