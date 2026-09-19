// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `restore_remote_backup` — admit a receiver partition into a secure domain.
//!
//! Runs on the receiver partition addressed by an outstanding `create_remote_backup`
//! hand-off. Reconstructs the receiver (emulator replay or direct `hw` open),
//! runs `sd_restore_remote_backup` over the receiver's masked sealing key, the
//! sender's evidence bundle, the policy, the hand-off `pok_remote_backup`, and
//! the domain's current `sd_mk_backup`, then installs the recovered BKS3 as the
//! receiver's device-local recovery pair, records the receiver as a domain
//! member, and marks the consumed hand-off as joined. No new domain is minted;
//! the receiver holds the same BKS3 as the backing partition.

use crate::cli::RestoreRemoteBackupArgs;
use crate::crypto::certs;
use crate::error::Error;
use crate::error::Result;
use crate::evidence::EvidenceBundle;
use crate::manifest;
use crate::manifest::DomainMember;
use crate::manifest::HandoffKind;
use crate::manifest::MemberManifest;
use crate::manifest::NamedArtifact;
use crate::manifest::PartitionManifest;
use crate::manifest::Role;
use crate::manifest::SCHEMA_VERSION;
use crate::manifest::SecureDomainManifest;
use crate::reconstruct;
use crate::util;
use crate::workspace::EvidenceRef;
use crate::workspace::Workspace;

/// Run `restore_remote_backup`.
pub fn run(ws: &Workspace, args: &RestoreRemoteBackupArgs) -> Result<()> {
    let receiver = args.partition.as_str();
    let domain = args.secure_domain.as_str();
    let sealing_key_name = args.sealing_key.as_str();

    let sender_ref =
        EvidenceRef::parse(&args.sender_evidence).map_err(|e| Error::InvalidArgs(e.to_string()))?;

    // The secure domain must exist.
    let domain_manifest_path = ws.secure_domain_manifest(domain);
    if !domain_manifest_path.exists() {
        return Err(Error::NotFound {
            what: "secure domain",
            path: ws.secure_domain_dir(domain),
        });
    }
    let mut domain_manifest: SecureDomainManifest = manifest::read(&domain_manifest_path)?;

    // Load and validate the receiver partition manifest.
    let receiver_manifest_path = ws.partition_manifest(receiver);
    if !receiver_manifest_path.exists() {
        return Err(Error::NotFound {
            what: "partition",
            path: ws.partition_dir(receiver),
        });
    }
    let mut receiver_manifest: PartitionManifest = manifest::read(&receiver_manifest_path)?;

    // The receiver must not already belong to a secure domain.
    if let Some(existing) = &receiver_manifest.secure_domain {
        return Err(Error::InvalidArgs(format!(
            "partition `{receiver}` already belongs to secure domain `{existing}`"
        )));
    }

    // The receiver must own the named sealing key.
    let receiver_key = receiver_manifest
        .sealing_keys
        .iter()
        .find(|k| k.name == sealing_key_name)
        .ok_or_else(|| Error::NotFound {
            what: "sealing key",
            path: ws.partition_sealing_key_dir(receiver, sealing_key_name),
        })?;

    // The receiver must not already be a member of the domain.
    if domain_manifest
        .members
        .iter()
        .any(|m| m.partition == receiver)
    {
        return Err(Error::InvalidArgs(format!(
            "partition `{receiver}` is already a member of secure domain `{domain}`"
        )));
    }

    // The receiver must be an outstanding (unconsumed) remote hand-off target.
    let handoff_index = domain_manifest
        .handoffs
        .iter()
        .position(|h| h.kind == HandoffKind::Remote && h.destination == receiver && !h.consumed)
        .ok_or_else(|| {
            Error::InvalidArgs(format!(
                "no outstanding remote hand-off for `{receiver}` in secure domain `{domain}`"
            ))
        })?;
    let handoff_source = domain_manifest.handoffs[handoff_index]
        .source_partition
        .clone();

    // The hand-off backup addressed to this receiver.
    let remote_backup_path = ws.secure_domain_remote_backup(domain, receiver);
    if !remote_backup_path.exists() {
        return Err(Error::NotFound {
            what: "remote backup",
            path: remote_backup_path.clone(),
        });
    }
    let src_remote_backup = util::read_file(&remote_backup_path)?;

    // The domain's current SD masking-key backup lives in the backing member
    // area; the SDK requires it as `prev_sd_mk_backup`.
    let backing = domain_manifest.backing_partition.name.clone();
    let sd_mk_path = ws.secure_domain_member_sd_mk(domain, &backing);
    if !sd_mk_path.exists() {
        return Err(Error::NotFound {
            what: "domain sd-mk backup",
            path: sd_mk_path.clone(),
        });
    }
    let prev_sd_mk_backup = util::read_file(&sd_mk_path)?;

    // Resolve and decode the sender evidence bundle.
    let sender = sender_ref.partition.as_str();
    let sender_evidence_path = ws.evidence_ref_path(&sender_ref);
    if !sender_evidence_path.exists() {
        return Err(Error::NotFound {
            what: "sender evidence",
            path: sender_evidence_path.clone(),
        });
    }
    let sender_evidence_bytes = util::read_file(&sender_evidence_path)?;
    let bundle = EvidenceBundle::decode(&sender_evidence_bytes)?;

    // Host-side fast-fail: the sender's three chains must certify the sender PID
    // key (evidence refs are workspace references, so the sender's artifacts
    // live in this same workspace).
    let sender_pid_der = util::read_file(&ws.partition_pid_public_key(sender))?;
    let sender_sec1 = certs::pub_sec1_from_spki(&sender_pid_der)
        .map_err(|e| Error::Internal(format!("parse sender pid public key: {e}")))?;
    if !bundle.chains_bind_pid(&sender_sec1) {
        return Err(Error::Internal(
            "sender evidence chains do not certify the sender pid public key".to_owned(),
        ));
    }

    // Load and verify the receiver's policy (the domain policy).
    let policy_bytes = util::read_file(&ws.root().join(&receiver_manifest.backing_policy.path))?;
    let policy_sha384 = util::sha384_hex(&policy_bytes);
    if policy_sha384 != receiver_manifest.backing_policy.sha384 {
        return Err(Error::PolicyMismatch(format!(
            "policy digest mismatch for `{receiver}`: manifest {}, file {policy_sha384}",
            receiver_manifest.backing_policy.sha384
        )));
    }

    // Load the receiver's persisted masked sealing-key blob.
    let masked = reconstruct::read_workspace_file(ws, &receiver_key.masked_key)?;

    // Open the operating session (emu reconstructs; hw opens directly).
    let operating = reconstruct::open(ws, &receiver_manifest)?;

    // One-shot HSM operation: HPKE-open the hand-off with the receiver's key,
    // authenticated by the sender evidence, and recover the domain BKS3. The
    // firmware performs the authoritative evidence, SATA-anchor,
    // report-signature and policy-binding checks.
    let restored = bundle
        .with_hsm_evidence(|ev| {
            operating.session.sd_restore_remote_backup(
                &masked,
                ev,
                &policy_bytes,
                &src_remote_backup,
                &prev_sd_mk_backup,
            )
        })
        .map_err(|e| Error::hsm("sd_restore_remote_backup", format!("{e:?}")))?;

    let now = util::now_rfc3339();

    // Install the recovered BKS3 as the receiver's device-local recovery pair.
    let member_dir = ws.secure_domain_member_dir(domain, receiver);
    util::create_dir_all(&member_dir)?;
    let pok_local_path = ws.secure_domain_member_pok_local(domain, receiver);
    let sd_mk_out_path = ws.secure_domain_member_sd_mk(domain, receiver);
    util::write_atomic(&pok_local_path, &restored.pok_local_backup)?;
    util::write_atomic(&sd_mk_out_path, &restored.sd_mk_backup)?;

    // Receiver member manifest.
    let member_manifest = MemberManifest {
        schema_version: SCHEMA_VERSION,
        kind: "member".to_owned(),
        partition: receiver.to_owned(),
        pid: receiver_manifest.pid.clone(),
        role: Role::Member,
        joined_via: "restore_remote_backup".to_owned(),
        source_partition: Some(handoff_source.clone()),
        source_handoff: Some(rel(ws, &remote_backup_path)?),
        created_utc: now.clone(),
        updated_utc: now.clone(),
        artifacts: vec![
            named_artifact("pok-local-backup.bin", &restored.pok_local_backup),
            named_artifact("sd-mk-backup.bin", &restored.sd_mk_backup),
        ],
    };
    manifest::write(
        &ws.secure_domain_member_manifest(domain, receiver),
        &member_manifest,
    )?;

    // Add the receiver to the domain and clear its outstanding hand-off.
    domain_manifest.members.push(DomainMember {
        partition: receiver.to_owned(),
        pid: receiver_manifest.pid.clone(),
        role: Role::Member,
        joined_via: "restore_remote_backup".to_owned(),
        source_partition: Some(handoff_source),
        created_utc: now,
    });
    domain_manifest.handoffs[handoff_index].consumed = true;
    manifest::write(&domain_manifest_path, &domain_manifest)?;

    // Record the receiver's membership.
    receiver_manifest.secure_domain = Some(domain.to_owned());
    manifest::write(&receiver_manifest_path, &receiver_manifest)?;

    print_summary(receiver, domain, sender, &restored);
    Ok(())
}

/// Build a [`NamedArtifact`] for a persisted member-area file.
fn named_artifact(name: &str, bytes: &[u8]) -> NamedArtifact {
    NamedArtifact {
        name: name.to_owned(),
        length: bytes.len() as u64,
        sha384: util::sha384_hex(bytes),
    }
}

fn print_summary(
    receiver: &str,
    domain: &str,
    sender: &str,
    restored: &azihsm_api::HsmSdRestoreResult,
) {
    println!("restore_remote_backup: `{receiver}` joined `{domain}`");
    println!("  sender:            {sender}");
    println!(
        "  pok_local_backup:  {} bytes",
        restored.pok_local_backup.len()
    );
    println!("  sd_mk_backup:      {} bytes", restored.sd_mk_backup.len());
    println!("  flavor:            {}", crate::flavor::FLAVOR);
}

fn rel(ws: &Workspace, abs: &std::path::Path) -> Result<String> {
    ws.relative(abs)
        .map_err(|err| Error::Internal(err.to_string()))
}
