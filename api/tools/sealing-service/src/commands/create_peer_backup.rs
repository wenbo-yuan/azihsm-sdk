// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `create_peer_backup` — hand a domain's BKS3 to a peer partition.
//!
//! Runs on an existing member partition. Reconstructs that partition (emulator
//! replay or direct `hw` open), recovers the domain BKS3 from the member's own
//! device-local `pok_local_backup`, and HPKE-Auth-seals the **same BKS3** to a
//! destination peer's attested public key — authenticated by the operating
//! partition's own masked sealing key. The result is written as a new
//! outstanding peer hand-off `peer-backups/<dest>.bin`; no new domain, member
//! area, or recovery point is minted. The peer becomes a member only after it
//! runs `restore_peer_backup`. Gated by the domain's `allow_peer_cloning`
//! policy flag, which the firmware enforces.

use crate::cli::CreatePeerBackupArgs;
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

/// Run `create_peer_backup`.
pub fn run(ws: &Workspace, args: &CreatePeerBackupArgs) -> Result<()> {
    let operating = args.partition.as_str();
    let domain = args.secure_domain.as_str();
    let sealing_key_name = args.sealing_key.as_str();

    let peer_ref =
        EvidenceRef::parse(&args.peer_evidence).map_err(|e| Error::InvalidArgs(e.to_string()))?;

    // The secure domain must exist.
    let domain_manifest_path = ws.secure_domain_manifest(domain);
    if !domain_manifest_path.exists() {
        return Err(Error::NotFound {
            what: "secure domain",
            path: ws.secure_domain_dir(domain),
        });
    }
    let mut domain_manifest: SecureDomainManifest = manifest::read(&domain_manifest_path)?;

    // Load the operating partition manifest.
    let operating_manifest_path = ws.partition_manifest(operating);
    if !operating_manifest_path.exists() {
        return Err(Error::NotFound {
            what: "partition",
            path: ws.partition_dir(operating),
        });
    }
    let operating_manifest: PartitionManifest = manifest::read(&operating_manifest_path)?;

    // The operating partition must be a member of this domain.
    let records_domain = operating_manifest.secure_domain.as_deref() == Some(domain);
    let is_member = domain_manifest
        .members
        .iter()
        .any(|m| m.partition == operating);
    if !records_domain || !is_member {
        return Err(Error::InvalidArgs(format!(
            "partition `{operating}` is not a member of secure domain `{domain}`"
        )));
    }

    // The operating partition must own the named sealing key.
    let operating_key = operating_manifest
        .sealing_keys
        .iter()
        .find(|k| k.name == sealing_key_name)
        .ok_or_else(|| Error::NotFound {
            what: "sealing key",
            path: ws.partition_sealing_key_dir(operating, sealing_key_name),
        })?;

    // The peer must be a distinct partition that is not yet a member.
    let peer = peer_ref.partition.as_str();
    if peer == operating {
        return Err(Error::InvalidArgs(format!(
            "peer partition must differ from the operating partition `{operating}`"
        )));
    }
    let peer_manifest_path = ws.partition_manifest(peer);
    if !peer_manifest_path.exists() {
        return Err(Error::NotFound {
            what: "peer partition",
            path: ws.partition_dir(peer),
        });
    }
    let peer_manifest: PartitionManifest = manifest::read(&peer_manifest_path)?;
    if domain_manifest.members.iter().any(|m| m.partition == peer) {
        return Err(Error::InvalidArgs(format!(
            "peer partition `{peer}` is already a member of secure domain `{domain}`"
        )));
    }
    let peer_key = peer_manifest
        .sealing_keys
        .iter()
        .find(|k| k.name == peer_ref.key)
        .ok_or_else(|| Error::NotFound {
            what: "peer sealing key",
            path: ws.partition_sealing_key_dir(peer, &peer_ref.key),
        })?;

    // Hand-offs are write-once per destination.
    let peer_backup_path = ws.secure_domain_peer_backup(domain, peer);
    if peer_backup_path.exists() {
        return Err(Error::AlreadyExists {
            what: "peer backup",
            path: peer_backup_path,
        });
    }

    // The operating partition's own device-local recovery point is the BKS3
    // source that is recovered and resealed to the peer.
    let pok_local_path = ws.secure_domain_member_pok_local(domain, operating);
    if !pok_local_path.exists() {
        return Err(Error::NotFound {
            what: "member pok-local backup",
            path: pok_local_path.clone(),
        });
    }
    let pok_local_backup = util::read_file(&pok_local_path)?;

    // Resolve and decode the peer (destination) evidence bundle. Evidence refs
    // are workspace references, so the peer's artifacts live in this workspace.
    let peer_evidence_path = ws.evidence_ref_path(&peer_ref);
    if !peer_evidence_path.exists() {
        return Err(Error::NotFound {
            what: "peer evidence",
            path: peer_evidence_path.clone(),
        });
    }
    let peer_evidence_bytes = util::read_file(&peer_evidence_path)?;
    let peer_bundle = EvidenceBundle::decode(&peer_evidence_bytes)?;
    let peer_evidence_sha384 = util::sha384_hex(&peer_evidence_bytes);

    // Host-side fast-fail: the peer's chains must certify the peer PID key.
    let peer_pid_der = util::read_file(&ws.partition_pid_public_key(peer))?;
    let peer_sec1 = certs::pub_sec1_from_spki(&peer_pid_der)
        .map_err(|e| Error::Internal(format!("parse peer pid public key: {e}")))?;
    if !peer_bundle.chains_bind_pid(&peer_sec1) {
        return Err(Error::Internal(
            "peer evidence chains do not certify the peer pid public key".to_owned(),
        ));
    }

    // Load and verify the operating partition's policy (the domain policy).
    let policy_bytes = util::read_file(&ws.root().join(&operating_manifest.backing_policy.path))?;
    let policy_sha384 = util::sha384_hex(&policy_bytes);
    if policy_sha384 != operating_manifest.backing_policy.sha384 {
        return Err(Error::PolicyMismatch(format!(
            "policy digest mismatch for `{operating}`: manifest {}, file {policy_sha384}",
            operating_manifest.backing_policy.sha384
        )));
    }

    // Load the operating partition's persisted masked sealing-key blob.
    let masked = reconstruct::read_workspace_file(ws, &operating_key.masked_key)?;

    // Open the operating session (emu reconstructs; hw opens directly).
    let session = reconstruct::open(ws, &operating_manifest)?;

    // One-shot HSM operation: recover the BKS3 from the operating partition's
    // device-local backup and HPKE-Auth-seal it to the peer. The firmware
    // performs the authoritative evidence, SATA-anchor, report-signature,
    // policy-binding and `allow_peer_cloning` checks.
    let peer_backup = peer_bundle
        .with_hsm_evidence(|peer_ev| {
            session.session.sd_create_peer_backup(
                &masked,
                peer_ev,
                &policy_bytes,
                &pok_local_backup,
            )
        })
        .map_err(|e| Error::hsm("sd_create_peer_backup", format!("{e:?}")))?;

    // Write the peer hand-off addressed to the destination peer.
    util::create_dir_all(&ws.secure_domain_peer_backups_dir(domain))?;
    util::write_atomic(&peer_backup_path, &peer_backup)?;

    // Record the peer as a new outstanding peer hand-off, sourced by the
    // operating partition.
    domain_manifest.handoffs.push(Handoff {
        kind: HandoffKind::Peer,
        destination: peer.to_owned(),
        pid: peer_manifest.pid.clone(),
        sealing_key_sha384: peer_key.public_key_sha384.clone(),
        evidence_ref: args.peer_evidence.clone(),
        evidence_sha384: peer_evidence_sha384,
        artifact: rel(ws, &peer_backup_path)?,
        created_by: "create_peer_backup".to_owned(),
        source_partition: operating.to_owned(),
        consumed: false,
    });
    manifest::write(&domain_manifest_path, &domain_manifest)?;

    print_summary(operating, domain, peer, peer_backup.len());
    Ok(())
}

fn print_summary(operating: &str, domain: &str, peer: &str, peer_backup_len: usize) {
    println!("create_peer_backup: `{operating}` handed `{domain}` to peer `{peer}`");
    println!("  peer:              {peer}");
    println!("  pok_peer_backup:   {peer_backup_len} bytes");
    println!("  flavor:            {}", crate::flavor::FLAVOR);
}

fn rel(ws: &Workspace, abs: &std::path::Path) -> Result<String> {
    ws.relative(abs)
        .map_err(|err| Error::Internal(err.to_string()))
}
