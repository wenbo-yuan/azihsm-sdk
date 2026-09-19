// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `reseal_remote_backup` — re-wrap a domain's BKS3 to a new destination.
//!
//! Runs on any partition addressed by an outstanding inbound remote hand-off
//! (`remote-backups/<reseal-partition>.bin`) — the partition need not have
//! joined the domain first. Reconstructs the partition (emulator replay or
//! direct `hw` open), HPKE-opens that inbound hand-off with its own masked
//! sealing key — authenticated by the original sender's evidence — and
//! HPKE-Auth-seals the recovered **same BKS3** to a new destination's attested
//! public key. The result is written as a new outstanding hand-off
//! `remote-backups/<dest>.bin`; no new domain, member area, or recovery point
//! is minted, and the reseal partition is not added as a member. This matches
//! the firmware, which needs only the inbound `pok_remote_backup` and never the
//! domain's `sd_mk_backup`, so a pure relay partition can forward the domain
//! without ever installing it locally. The destination becomes a member only
//! after it runs `restore_remote_backup` against this reseal output.

use crate::cli::ResealRemoteBackupArgs;
use crate::crypto::certs;
use crate::error::Error;
use crate::error::Result;
use crate::evidence::EvidenceBundle;
use crate::manifest;
use crate::manifest::Handoff;
use crate::manifest::HandoffKind;
use crate::manifest::PartitionManifest;
use crate::manifest::SecureDomainManifest;
use crate::reconstruct;
use crate::util;
use crate::workspace::EvidenceRef;
use crate::workspace::Workspace;

/// Run `reseal_remote_backup`.
pub fn run(ws: &Workspace, args: &ResealRemoteBackupArgs) -> Result<()> {
    let reseal = args.partition.as_str();
    let domain = args.secure_domain.as_str();
    let sealing_key_name = args.sealing_key.as_str();

    let src_ref =
        EvidenceRef::parse(&args.sender_evidence).map_err(|e| Error::InvalidArgs(e.to_string()))?;
    let dest_ref = EvidenceRef::parse(&args.receiver_evidence)
        .map_err(|e| Error::InvalidArgs(e.to_string()))?;

    // The secure domain must exist.
    let domain_manifest_path = ws.secure_domain_manifest(domain);
    if !domain_manifest_path.exists() {
        return Err(Error::NotFound {
            what: "secure domain",
            path: ws.secure_domain_dir(domain),
        });
    }
    let mut domain_manifest: SecureDomainManifest = manifest::read(&domain_manifest_path)?;

    // Load the reseal partition manifest.
    let reseal_manifest_path = ws.partition_manifest(reseal);
    if !reseal_manifest_path.exists() {
        return Err(Error::NotFound {
            what: "partition",
            path: ws.partition_dir(reseal),
        });
    }
    let reseal_manifest: PartitionManifest = manifest::read(&reseal_manifest_path)?;

    // Match the firmware: any partition addressed by an outstanding inbound
    // remote hand-off can reseal it forward — it need not have joined the
    // domain. `sd_reseal_remote_backup` recovers BKS3 from that inbound
    // `pok_remote_backup` alone (unwrapped with the partition's own sealing key
    // and authenticated by the sender's evidence) and never consumes the
    // domain's `sd_mk_backup`, so no local member material is required. This
    // admits a pure relay partition that transports the domain to a third
    // partition without ever installing it locally.
    let inbound_key_sha384 = domain_manifest
        .handoffs
        .iter()
        .find(|h| h.kind == HandoffKind::Remote && h.destination == reseal)
        .map(|h| h.sealing_key_sha384.clone())
        .ok_or_else(|| {
            Error::InvalidArgs(format!(
                "partition `{reseal}` has no inbound remote hand-off in secure domain `{domain}`"
            ))
        })?;

    // The reseal partition must own the named sealing key.
    let reseal_key = reseal_manifest
        .sealing_keys
        .iter()
        .find(|k| k.name == sealing_key_name)
        .ok_or_else(|| Error::NotFound {
            what: "sealing key",
            path: ws.partition_sealing_key_dir(reseal, sealing_key_name),
        })?;

    // The named sealing key must be the recipient key the inbound hand-off was
    // sealed to; otherwise the firmware HPKE-open of the hand-off would fail.
    if reseal_key.public_key_sha384 != inbound_key_sha384 {
        return Err(Error::InvalidArgs(format!(
            "sealing key `{sealing_key_name}` is not the recipient key for `{reseal}`'s inbound remote hand-off in `{domain}`"
        )));
    }

    // The destination must be a distinct partition that is not yet a member.
    let dest = dest_ref.partition.as_str();
    let dest_manifest_path = ws.partition_manifest(dest);
    if !dest_manifest_path.exists() {
        return Err(Error::NotFound {
            what: "destination partition",
            path: ws.partition_dir(dest),
        });
    }
    let dest_manifest: PartitionManifest = manifest::read(&dest_manifest_path)?;
    if domain_manifest.members.iter().any(|m| m.partition == dest) {
        return Err(Error::InvalidArgs(format!(
            "destination partition `{dest}` is already a member of secure domain `{domain}`"
        )));
    }
    let dest_key = dest_manifest
        .sealing_keys
        .iter()
        .find(|k| k.name == dest_ref.key)
        .ok_or_else(|| Error::NotFound {
            what: "destination sealing key",
            path: ws.partition_sealing_key_dir(dest, &dest_ref.key),
        })?;

    // Hand-offs are write-once per destination.
    let dest_backup_path = ws.secure_domain_remote_backup(domain, dest);
    if dest_backup_path.exists() {
        return Err(Error::AlreadyExists {
            what: "remote backup",
            path: dest_backup_path,
        });
    }

    // The inbound hand-off this partition can open lives at
    // `remote-backups/<reseal-partition>.bin`.
    let src_backup_path = ws.secure_domain_remote_backup(domain, reseal);
    if !src_backup_path.exists() {
        return Err(Error::NotFound {
            what: "source remote backup",
            path: src_backup_path.clone(),
        });
    }
    let src_remote_backup = util::read_file(&src_backup_path)?;

    // Resolve and decode both evidence bundles. Evidence refs are workspace
    // references, so both partitions' artifacts live in this same workspace.
    let src_partition = src_ref.partition.as_str();
    let src_evidence_path = ws.evidence_ref_path(&src_ref);
    if !src_evidence_path.exists() {
        return Err(Error::NotFound {
            what: "sender evidence",
            path: src_evidence_path.clone(),
        });
    }
    let src_evidence_bytes = util::read_file(&src_evidence_path)?;
    let src_bundle = EvidenceBundle::decode(&src_evidence_bytes)?;

    let dest_evidence_path = ws.evidence_ref_path(&dest_ref);
    if !dest_evidence_path.exists() {
        return Err(Error::NotFound {
            what: "destination evidence",
            path: dest_evidence_path.clone(),
        });
    }
    let dest_evidence_bytes = util::read_file(&dest_evidence_path)?;
    let dest_bundle = EvidenceBundle::decode(&dest_evidence_bytes)?;
    let dest_evidence_sha384 = util::sha384_hex(&dest_evidence_bytes);

    // Host-side fast-fail: each bundle's chains must certify their PID key.
    let src_pid_der = util::read_file(&ws.partition_pid_public_key(src_partition))?;
    let src_sec1 = certs::pub_sec1_from_spki(&src_pid_der)
        .map_err(|e| Error::Internal(format!("parse sender pid public key: {e}")))?;
    if !src_bundle.chains_bind_pid(&src_sec1) {
        return Err(Error::Internal(
            "sender evidence chains do not certify the sender pid public key".to_owned(),
        ));
    }
    let dest_pid_der = util::read_file(&ws.partition_pid_public_key(dest))?;
    let dest_sec1 = certs::pub_sec1_from_spki(&dest_pid_der)
        .map_err(|e| Error::Internal(format!("parse destination pid public key: {e}")))?;
    if !dest_bundle.chains_bind_pid(&dest_sec1) {
        return Err(Error::Internal(
            "destination evidence chains do not certify the destination pid public key".to_owned(),
        ));
    }

    // Load and verify the reseal partition's policy (the domain policy).
    let policy_bytes = util::read_file(&ws.root().join(&reseal_manifest.backing_policy.path))?;
    let policy_sha384 = util::sha384_hex(&policy_bytes);
    if policy_sha384 != reseal_manifest.backing_policy.sha384 {
        return Err(Error::PolicyMismatch(format!(
            "policy digest mismatch for `{reseal}`: manifest {}, file {policy_sha384}",
            reseal_manifest.backing_policy.sha384
        )));
    }

    // Load the reseal partition's persisted masked sealing-key blob.
    let masked = reconstruct::read_workspace_file(ws, &reseal_key.masked_key)?;

    // Open the operating session (emu reconstructs; hw opens directly).
    let operating = reconstruct::open(ws, &reseal_manifest)?;

    // One-shot HSM operation: HPKE-open the inbound hand-off (authenticated by
    // the source evidence) and HPKE-Auth-seal the recovered BKS3 to the
    // destination. Both evidence bundles are borrowed simultaneously by nesting
    // the borrow closures. The firmware performs the authoritative evidence,
    // SATA-anchor, report-signature and policy-binding checks on both.
    let resealed = src_bundle
        .with_hsm_evidence(|src_ev| {
            dest_bundle.with_hsm_evidence(|dest_ev| {
                operating.session.sd_reseal_remote_backup(
                    &masked,
                    src_ev,
                    dest_ev,
                    &policy_bytes,
                    &src_remote_backup,
                )
            })
        })
        .map_err(|e| Error::hsm("sd_reseal_remote_backup", format!("{e:?}")))?;

    // Write the resealed hand-off addressed to the destination.
    util::create_dir_all(&ws.secure_domain_remote_backups_dir(domain))?;
    util::write_atomic(&dest_backup_path, &resealed)?;

    // Record the destination as a new outstanding remote hand-off, sourced by
    // the reseal partition.
    domain_manifest.handoffs.push(Handoff {
        kind: HandoffKind::Remote,
        destination: dest.to_owned(),
        pid: dest_manifest.pid.clone(),
        sealing_key_sha384: dest_key.public_key_sha384.clone(),
        evidence_ref: args.receiver_evidence.clone(),
        evidence_sha384: dest_evidence_sha384,
        artifact: rel(ws, &dest_backup_path)?,
        created_by: "reseal_remote_backup".to_owned(),
        source_partition: reseal.to_owned(),
        consumed: false,
    });
    manifest::write(&domain_manifest_path, &domain_manifest)?;

    print_summary(reseal, domain, dest, resealed.len());
    Ok(())
}

fn print_summary(reseal: &str, domain: &str, dest: &str, resealed_len: usize) {
    println!("reseal_remote_backup: `{reseal}` resealed `{domain}` to `{dest}`");
    println!("  destination:       {dest}");
    println!("  pok_remote_backup: {resealed_len} bytes");
    println!("  flavor:            {}", crate::flavor::FLAVOR);
}

fn rel(ws: &Workspace, abs: &std::path::Path) -> Result<String> {
    ws.relative(abs)
        .map_err(|err| Error::Internal(err.to_string()))
}
