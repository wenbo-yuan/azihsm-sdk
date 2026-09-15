// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `restore_local_backup` — refresh a member's own device-local recovery point.
//!
//! This is the self-recovery path: the operating partition is already a member
//! of the secure domain and re-masks its own BKS3 at the current `{svn, owner}`.
//! It takes no sealing key, no evidence, and no policy. The CLI reads the
//! partition's own `members/<partition>/{pok-local-backup,sd-mk-backup}.bin`,
//! reconstructs the partition (emulator replay or direct `hw` open), runs
//! `sd_restore_local_backup`, and writes the refreshed pair back **in place**.
//! No new domain or backup is minted; the BKS3 identity, policy binding, and
//! membership are unchanged.

use crate::cli::RestoreLocalBackupArgs;
use crate::error::Error;
use crate::error::Result;
use crate::manifest;
use crate::manifest::MemberManifest;
use crate::manifest::NamedArtifact;
use crate::manifest::PartitionManifest;
use crate::manifest::SecureDomainManifest;
use crate::reconstruct;
use crate::util;
use crate::workspace::Workspace;

/// Run `restore_local_backup`.
pub fn run(ws: &Workspace, args: &RestoreLocalBackupArgs) -> Result<()> {
    let partition = args.partition.as_str();
    let domain = args.secure_domain.as_str();

    // The secure domain must exist.
    let domain_manifest_path = ws.secure_domain_manifest(domain);
    if !domain_manifest_path.exists() {
        return Err(Error::NotFound {
            what: "secure domain",
            path: ws.secure_domain_dir(domain),
        });
    }
    let domain_manifest: SecureDomainManifest = manifest::read(&domain_manifest_path)?;

    // Load the partition manifest.
    let partition_manifest_path = ws.partition_manifest(partition);
    if !partition_manifest_path.exists() {
        return Err(Error::NotFound {
            what: "partition",
            path: ws.partition_dir(partition),
        });
    }
    let partition_manifest: PartitionManifest = manifest::read(&partition_manifest_path)?;

    // The partition must record membership in this exact domain.
    match &partition_manifest.secure_domain {
        Some(existing) if existing == domain => {}
        Some(existing) => {
            return Err(Error::InvalidArgs(format!(
                "partition `{partition}` belongs to secure domain `{existing}`, not `{domain}`"
            )));
        }
        None => {
            return Err(Error::InvalidArgs(format!(
                "partition `{partition}` does not belong to any secure domain"
            )));
        }
    }

    // The partition must be a recorded member of the domain.
    if !domain_manifest
        .members
        .iter()
        .any(|m| m.partition == partition)
    {
        return Err(Error::InvalidArgs(format!(
            "partition `{partition}` is not a member of secure domain `{domain}`"
        )));
    }

    // The partition's own member area must exist.
    let member_manifest_path = ws.secure_domain_member_manifest(domain, partition);
    if !member_manifest_path.exists() {
        return Err(Error::NotFound {
            what: "member manifest",
            path: member_manifest_path.clone(),
        });
    }
    let mut member_manifest: MemberManifest = manifest::read(&member_manifest_path)?;

    // Read the current device-local recovery pair and verify it matches the
    // digests recorded in the member manifest.
    let pok_local_path = ws.secure_domain_member_pok_local(domain, partition);
    let sd_mk_path = ws.secure_domain_member_sd_mk(domain, partition);
    let pok_local_backup = read_and_verify(
        ws,
        domain,
        partition,
        &member_manifest,
        "pok-local-backup.bin",
    )?;
    let sd_mk_backup =
        read_and_verify(ws, domain, partition, &member_manifest, "sd-mk-backup.bin")?;

    // Open the operating session (emu reconstructs; hw opens directly).
    let operating = reconstruct::open(ws, &partition_manifest)?;

    // One-shot HSM operation: recover the BKS3 from the device-local pair and
    // re-mask it at the current `{svn, owner}`.
    let restored = operating
        .session
        .sd_restore_local_backup(&pok_local_backup, &sd_mk_backup)
        .map_err(|e| Error::hsm("sd_restore_local_backup", format!("{e:?}")))?;

    // Refresh the recovery pair in place (atomic replacement, not a new copy).
    util::write_atomic(&pok_local_path, &restored.pok_local_backup)?;
    util::write_atomic(&sd_mk_path, &restored.sd_mk_backup)?;

    // Update the member manifest's artifact digests and timestamp.
    let now = util::now_rfc3339();
    member_manifest.updated_utc = now;
    member_manifest.artifacts = vec![
        named_artifact("pok-local-backup.bin", &restored.pok_local_backup),
        named_artifact("sd-mk-backup.bin", &restored.sd_mk_backup),
    ];
    manifest::write(&member_manifest_path, &member_manifest)?;

    print_summary(partition, domain, &restored);
    Ok(())
}

/// Read a member-area artifact and verify its digest matches the member
/// manifest's recorded value.
fn read_and_verify(
    ws: &Workspace,
    domain: &str,
    partition: &str,
    member: &MemberManifest,
    name: &str,
) -> Result<Vec<u8>> {
    let recorded = member
        .artifacts
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| Error::Manifest {
            path: ws.secure_domain_member_manifest(domain, partition),
            detail: format!("member manifest is missing artifact `{name}`"),
        })?;
    let path = ws.secure_domain_member_dir(domain, partition).join(name);
    if !path.exists() {
        return Err(Error::NotFound {
            what: "member artifact",
            path,
        });
    }
    let bytes = util::read_file(&path)?;
    let actual = util::sha384_hex(&bytes);
    if actual != recorded.sha384 {
        return Err(Error::Manifest {
            path,
            detail: format!(
                "member artifact `{name}` digest mismatch: manifest {}, file {actual}",
                recorded.sha384
            ),
        });
    }
    Ok(bytes)
}

/// Build a [`NamedArtifact`] for a persisted member-area file.
fn named_artifact(name: &str, bytes: &[u8]) -> NamedArtifact {
    NamedArtifact {
        name: name.to_owned(),
        length: bytes.len() as u64,
        sha384: util::sha384_hex(bytes),
    }
}

fn print_summary(partition: &str, domain: &str, restored: &azihsm_api::HsmSdRestoreResult) {
    println!("restore_local_backup: refreshed `{partition}` in `{domain}`");
    println!(
        "  pok_local_backup:  {} bytes",
        restored.pok_local_backup.len()
    );
    println!("  sd_mk_backup:      {} bytes", restored.sd_mk_backup.len());
    println!("  flavor:            {}", crate::flavor::FLAVOR);
}
