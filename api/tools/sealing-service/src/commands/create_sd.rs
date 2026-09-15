// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `create_sd` — mint a new security domain from a backing partition.
//!
//! Reconstructs the backing partition (emulator replay or direct `hw` open),
//! runs `sd_create_remote_backup` over the backing partition's masked sealing
//! key, the receiver's evidence bundle, and the backing policy, and persists
//! the resulting domain: the backing partition's device-local recovery pair
//! (`members/<backing>/{pok-local-backup,sd-mk-backup}.bin`), the outbound
//! hand-off addressed to the receiver (`remote-backups/<receiver>.bin`), and
//! the `secure-domain.json` / `member.json` manifests. In a self-backup the
//! receiver evidence is the backing partition's own; in a cross-partition
//! backup it addresses a distinct receiver that joins later via a remote
//! restore.

use crate::cli::CreateSdArgs;
use crate::crypto::certs;
use crate::error::Error;
use crate::error::Result;
use crate::evidence::EvidenceBundle;
use crate::manifest;
use crate::manifest::BackupScope;
use crate::manifest::DomainMember;
use crate::manifest::Handoff;
use crate::manifest::HandoffKind;
use crate::manifest::MemberManifest;
use crate::manifest::NamedArtifact;
use crate::manifest::PartitionManifest;
use crate::manifest::PartitionRef;
use crate::manifest::Role;
use crate::manifest::SCHEMA_VERSION;
use crate::manifest::SecureDomainManifest;
use crate::reconstruct;
use crate::util;
use crate::workspace::EvidenceRef;
use crate::workspace::Workspace;

/// Run `create_sd`.
pub fn run(ws: &Workspace, args: &CreateSdArgs) -> Result<()> {
    let backing = args.partition.as_str();
    let domain = args.secure_domain.as_str();
    let sealing_key_name = args.sealing_key.as_str();

    let evidence_ref = EvidenceRef::parse(&args.receiver_evidence)
        .map_err(|e| Error::InvalidArgs(e.to_string()))?;

    // Load and validate the backing partition manifest.
    let backing_manifest_path = ws.partition_manifest(backing);
    if !backing_manifest_path.exists() {
        return Err(Error::NotFound {
            what: "partition",
            path: ws.partition_dir(backing),
        });
    }
    let mut backing_manifest: PartitionManifest = manifest::read(&backing_manifest_path)?;

    // The backing partition must belong to no secure domain yet.
    if let Some(existing) = &backing_manifest.secure_domain {
        return Err(Error::InvalidArgs(format!(
            "partition `{backing}` already belongs to secure domain `{existing}`"
        )));
    }

    // The backing partition must own the named sealing key.
    let backing_key_index = backing_manifest
        .sealing_keys
        .iter()
        .position(|k| k.name == sealing_key_name)
        .ok_or_else(|| Error::NotFound {
            what: "sealing key",
            path: ws.partition_sealing_key_dir(backing, sealing_key_name),
        })?;

    // The secure domain must not already exist.
    if ws.secure_domain_dir(domain).exists() {
        return Err(Error::AlreadyExists {
            what: "secure domain",
            path: ws.secure_domain_dir(domain),
        });
    }

    // Resolve and decode the receiver evidence bundle.
    let evidence_path = ws.evidence_ref_path(&evidence_ref);
    if !evidence_path.exists() {
        return Err(Error::NotFound {
            what: "receiver evidence",
            path: evidence_path.clone(),
        });
    }
    let evidence_bytes = util::read_file(&evidence_path)?;
    let bundle = EvidenceBundle::decode(&evidence_bytes)?;
    let evidence_sha384 = util::sha384_hex(&evidence_bytes);

    // A self-backup names the backing partition as its own receiver.
    let is_self = evidence_ref.partition == backing;
    let backup_scope = if is_self {
        BackupScope::SelfBackup
    } else {
        BackupScope::CrossPartition
    };

    // Load the receiver partition manifest (evidence refs are workspace
    // references, so the receiver's artifacts live in this same workspace).
    let receiver = evidence_ref.partition.as_str();
    let receiver_manifest_path = ws.partition_manifest(receiver);
    if !receiver_manifest_path.exists() {
        return Err(Error::NotFound {
            what: "receiver partition",
            path: ws.partition_dir(receiver),
        });
    }
    let receiver_manifest: PartitionManifest = manifest::read(&receiver_manifest_path)?;
    let receiver_key = receiver_manifest
        .sealing_keys
        .iter()
        .find(|k| k.name == evidence_ref.key)
        .ok_or_else(|| Error::NotFound {
            what: "receiver sealing key",
            path: ws.partition_sealing_key_dir(receiver, &evidence_ref.key),
        })?;

    // Host-side fast-fail: the three chains must certify the receiver PID key.
    let receiver_pid_der = util::read_file(&ws.partition_pid_public_key(receiver))?;
    let receiver_sec1 = certs::pub_sec1_from_spki(&receiver_pid_der)
        .map_err(|e| Error::Internal(format!("parse receiver pid public key: {e}")))?;
    if !bundle.chains_bind_pid(&receiver_sec1) {
        return Err(Error::Internal(
            "receiver evidence chains do not certify the receiver pid public key".to_owned(),
        ));
    }

    // Load and verify the backing policy the manifest records.
    let policy_bytes = util::read_file(&ws.root().join(&backing_manifest.backing_policy.path))?;
    let policy_sha384 = util::sha384_hex(&policy_bytes);
    if policy_sha384 != backing_manifest.backing_policy.sha384 {
        return Err(Error::PolicyMismatch(format!(
            "backing policy digest mismatch for `{backing}`: manifest {}, file {policy_sha384}",
            backing_manifest.backing_policy.sha384
        )));
    }

    // Load the backing partition's persisted masked sealing-key blob.
    let masked = reconstruct::read_workspace_file(
        ws,
        &backing_manifest.sealing_keys[backing_key_index].masked_key,
    )?;

    // Open the operating session (emu reconstructs; hw opens directly).
    let operating = reconstruct::open(ws, &backing_manifest)?;

    // One-shot HSM operation: create the domain from the masked key, the
    // receiver evidence, and the policy. The firmware performs the
    // authoritative evidence, SATA-anchor, report-signature and policy-binding
    // checks; a failure surfaces as an HSM error.
    let result = bundle
        .with_hsm_evidence(|ev| {
            operating
                .session
                .sd_create_remote_backup(&masked, ev, &policy_bytes)
        })
        .map_err(|e| Error::hsm("sd_create_remote_backup", format!("{e:?}")))?;

    let now = util::now_rfc3339();

    // Persist the domain policy (a byte-identical copy) and staging dirs.
    util::create_dir_all(&ws.secure_domain_dir(domain))?;
    let domain_policy_path = ws.secure_domain_policy(domain);
    util::write_atomic(&domain_policy_path, &policy_bytes)?;

    // Backing partition's device-local recovery pair.
    let member_dir = ws.secure_domain_member_dir(domain, backing);
    util::create_dir_all(&member_dir)?;
    let pok_local_path = ws.secure_domain_member_pok_local(domain, backing);
    let sd_mk_path = ws.secure_domain_member_sd_mk(domain, backing);
    util::write_atomic(&pok_local_path, &result.pok_local_backup)?;
    util::write_atomic(&sd_mk_path, &result.sd_mk_backup)?;

    // Outbound hand-off addressed to the receiver.
    util::create_dir_all(&ws.secure_domain_remote_backups_dir(domain))?;
    let remote_backup_path = ws.secure_domain_remote_backup(domain, receiver);
    util::write_atomic(&remote_backup_path, &result.pok_remote_backup)?;

    // Backing member manifest.
    let member_manifest = MemberManifest {
        schema_version: SCHEMA_VERSION,
        kind: "member".to_owned(),
        partition: backing.to_owned(),
        pid: backing_manifest.pid.clone(),
        role: Role::Backing,
        joined_via: "create_sd".to_owned(),
        source_partition: None,
        source_handoff: None,
        created_utc: now.clone(),
        updated_utc: now.clone(),
        artifacts: vec![
            named_artifact("pok-local-backup.bin", &result.pok_local_backup),
            named_artifact("sd-mk-backup.bin", &result.sd_mk_backup),
        ],
    };
    manifest::write(
        &ws.secure_domain_member_manifest(domain, backing),
        &member_manifest,
    )?;

    // Secure-domain manifest. The receiver is an outstanding hand-off unless
    // this is a self-backup, in which case the backing partition is already the
    // sole member and the hand-off is immediately consumed.
    let domain_manifest = SecureDomainManifest {
        schema_version: SCHEMA_VERSION,
        kind: "secure-domain".to_owned(),
        name: domain.to_owned(),
        created_utc: now.clone(),
        authority_set: backing_manifest.authority_set.clone(),
        policy: manifest::FileRef {
            path: rel(ws, &domain_policy_path)?,
            sha384: policy_sha384,
        },
        backing_partition: PartitionRef {
            name: backing.to_owned(),
            pid: backing_manifest.pid.clone(),
        },
        backup_scope,
        members: vec![DomainMember {
            partition: backing.to_owned(),
            pid: backing_manifest.pid.clone(),
            role: Role::Backing,
            joined_via: "create_sd".to_owned(),
            source_partition: None,
            created_utc: now.clone(),
        }],
        handoffs: vec![Handoff {
            kind: HandoffKind::Remote,
            destination: receiver.to_owned(),
            pid: receiver_manifest.pid.clone(),
            sealing_key_sha384: receiver_key.public_key_sha384.clone(),
            evidence_ref: args.receiver_evidence.clone(),
            evidence_sha384,
            artifact: rel(ws, &remote_backup_path)?,
            created_by: "create_sd".to_owned(),
            source_partition: backing.to_owned(),
            consumed: is_self,
        }],
    };
    manifest::write(&ws.secure_domain_manifest(domain), &domain_manifest)?;

    // Record the backing partition's membership.
    backing_manifest.secure_domain = Some(domain.to_owned());
    manifest::write(&backing_manifest_path, &backing_manifest)?;

    print_summary(backing, domain, receiver, is_self, &result);
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
    backing: &str,
    domain: &str,
    receiver: &str,
    is_self: bool,
    result: &azihsm_api::HsmSdRemoteBackupResult,
) {
    let scope = if is_self { "self" } else { "cross-partition" };
    println!("create_sd: created `{domain}` backed by `{backing}` ({scope})");
    println!("  receiver:          {receiver}");
    println!(
        "  pok_remote_backup: {} bytes",
        result.pok_remote_backup.len()
    );
    println!(
        "  pok_local_backup:  {} bytes",
        result.pok_local_backup.len()
    );
    println!("  sd_mk_backup:      {} bytes", result.sd_mk_backup.len());
    println!("  flavor:            {}", crate::flavor::FLAVOR);
}

fn rel(ws: &Workspace, abs: &std::path::Path) -> Result<String> {
    ws.relative(abs)
        .map_err(|err| Error::Internal(err.to_string()))
}
