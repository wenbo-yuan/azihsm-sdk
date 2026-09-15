// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `key_report` — attest a partition's persisted masked sealing key.
//!
//! Reconstructs the initialized partition (emulator replay or direct `hw`
//! open), generates a COSE_Sign1 key report over the persisted masked sealing
//! blob, packages that report together with the partition's three DER
//! certificate chains into a persisted evidence bundle, and records the bundle
//! in the partition manifest. The bundle is the receiver-side evidence a peer's
//! `create_sd` consumes to admit this partition into a security domain.

use azihsm_ddi_tbor_types::KEY_REPORT_DATA_LEN;

use crate::cli::KeyReportArgs;
use crate::crypto::certs;
use crate::error::Error;
use crate::error::Result;
use crate::evidence::EvidenceBundle;
use crate::manifest;
use crate::manifest::PartitionManifest;
use crate::reconstruct;
use crate::util;
use crate::workspace::Workspace;

/// Run `key_report`.
pub fn run(ws: &Workspace, args: &KeyReportArgs) -> Result<()> {
    let partition = args.partition.as_str();
    let key_name = args.sealing_key.as_str();
    let report_name = args.report.as_str();

    // The partition must already be initialized.
    let manifest_path = ws.partition_manifest(partition);
    if !manifest_path.exists() {
        return Err(Error::NotFound {
            what: "partition",
            path: ws.partition_dir(partition),
        });
    }
    let mut part_manifest: PartitionManifest = manifest::read(&manifest_path)?;

    // Locate the sealing key the report attests.
    let key_index = part_manifest
        .sealing_keys
        .iter()
        .position(|k| k.name == key_name)
        .ok_or_else(|| Error::NotFound {
            what: "sealing key",
            path: ws.partition_sealing_key_dir(partition, key_name),
        })?;

    // Never overwrite an existing evidence bundle of the same name.
    let evidence_path = ws.partition_sealing_key_evidence(partition, key_name, report_name);
    if evidence_path.exists() {
        return Err(Error::AlreadyExists {
            what: "evidence bundle",
            path: evidence_path.clone(),
        });
    }

    // Report data bound into the attestation: a caller-supplied 128-byte file
    // or the all-zero default. The device rejects any other length.
    let report_data = load_report_data(args)?;

    // The persisted masked sealing blob is attested as-is; there is no public
    // API to reconstruct an `HsmSealingKey` from it, so `sd_key_report`
    // consumes the raw bytes on a freshly opened operating session.
    let masked =
        reconstruct::read_workspace_file(ws, &part_manifest.sealing_keys[key_index].masked_key)?;

    // Open the operating session (emu reconstructs; hw opens directly).
    let operating = reconstruct::open(ws, &part_manifest)?;

    // Two-call size protocol: a `None` report queries the maximum length; the
    // second call fills the buffer and returns the actual report length.
    let max_len = operating
        .session
        .sd_key_report(&masked, &report_data, None)
        .map_err(|e| Error::hsm("sd_key_report(size)", format!("{e:?}")))?;
    let mut report = vec![0u8; max_len];
    let actual = operating
        .session
        .sd_key_report(&masked, &report_data, Some(&mut report))
        .map_err(|e| Error::hsm("sd_key_report", format!("{e:?}")))?;
    report.truncate(actual);
    if report.is_empty() {
        return Err(Error::hsm("sd_key_report", "key report is empty"));
    }

    // Load the partition's three certificate chains, ordered `[root, leaf]`.
    let manufacturer_chain = load_chain(ws, &part_manifest.attestation.manufacturer_chain)?;
    let owner_chain = load_chain(ws, &part_manifest.attestation.owner_chain)?;
    let partition_owner_chain = load_chain(ws, &part_manifest.attestation.partition_owner_chain)?;

    // Consistency check: every chain's leaf must certify the partition PID
    // public key — the same key that signs the report. This binds the
    // certificate chains to the attested identity.
    verify_chains_bind_pid(
        ws,
        &part_manifest,
        &[
            (&manufacturer_chain, "manufacturer"),
            (&owner_chain, "owner"),
            (&partition_owner_chain, "partition-owner"),
        ],
    )?;

    // Package and persist the evidence bundle.
    let bundle = EvidenceBundle::new(
        manufacturer_chain,
        owner_chain,
        partition_owner_chain,
        report,
    );
    let encoded = bundle.encode();
    util::create_dir_all(&ws.partition_sealing_key_evidence_dir(partition, key_name))?;
    util::write_atomic(&evidence_path, &encoded)?;

    // Record the bundle in the manifest.
    let rel_path = rel(ws, &evidence_path)?;
    part_manifest.sealing_keys[key_index]
        .reports
        .push(rel_path.clone());
    manifest::write(&manifest_path, &part_manifest)?;

    print_summary(
        partition,
        key_name,
        report_name,
        bundle.report().len(),
        &util::sha384_hex(&encoded),
    );
    Ok(())
}

/// Load the caller-supplied report data or default to all zeros. A supplied
/// file must be exactly [`KEY_REPORT_DATA_LEN`] bytes.
fn load_report_data(args: &KeyReportArgs) -> Result<[u8; KEY_REPORT_DATA_LEN]> {
    let mut data = [0u8; KEY_REPORT_DATA_LEN];
    if let Some(path) = &args.report_data {
        let bytes = util::read_file(path)?;
        if bytes.len() != KEY_REPORT_DATA_LEN {
            return Err(Error::InvalidArgs(format!(
                "report data `{}` must be {KEY_REPORT_DATA_LEN} bytes, got {}",
                path.display(),
                bytes.len()
            )));
        }
        data.copy_from_slice(&bytes);
    }
    Ok(data)
}

/// Load every DER certificate in a manifest-referenced chain, preserving the
/// recorded `[root, leaf]` order.
fn load_chain(ws: &Workspace, chain: &[String]) -> Result<Vec<Vec<u8>>> {
    if chain.is_empty() {
        return Err(Error::Internal(
            "partition certificate chain is empty".to_owned(),
        ));
    }
    chain
        .iter()
        .map(|rel_path| reconstruct::read_workspace_file(ws, rel_path))
        .collect()
}

/// Verify that each chain's leaf certificate embeds the partition PID public
/// key (its 97-byte SEC1 point), binding the chains to the report signer.
fn verify_chains_bind_pid(
    ws: &Workspace,
    part_manifest: &PartitionManifest,
    chains: &[(&Vec<Vec<u8>>, &str)],
) -> Result<()> {
    let pid_der = reconstruct::read_workspace_file(ws, &part_manifest.pid_public_key.path)?;
    let sec1 = certs::pub_sec1_from_spki(&pid_der)
        .map_err(|e| Error::Internal(format!("parse partition pid public key: {e}")))?;

    for (chain, label) in chains {
        let leaf = chain
            .last()
            .ok_or_else(|| Error::Internal(format!("{label} certificate chain is empty")))?;
        if !leaf.windows(sec1.len()).any(|w| w == sec1) {
            return Err(Error::Internal(format!(
                "{label} chain leaf does not certify the partition pid public key"
            )));
        }
    }
    Ok(())
}

fn print_summary(
    partition: &str,
    key_name: &str,
    report_name: &str,
    report_len: usize,
    evidence_sha384: &str,
) {
    println!("key_report: attested `{key_name}` on `{partition}`");
    println!("  report:          {report_name} ({report_len} bytes)");
    println!("  evidence sha384: {evidence_sha384}");
    println!("  flavor:          {}", crate::flavor::FLAVOR);
}

fn rel(ws: &Workspace, abs: &std::path::Path) -> Result<String> {
    ws.relative(abs)
        .map_err(|err| Error::Internal(err.to_string()))
}
