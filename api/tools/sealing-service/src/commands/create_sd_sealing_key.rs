// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `create_sd_sealing_key` — generate one secure-domain sealing key on an
//! initialized partition.
//!
//! Implements the `create_sd_sealing_key` command contract from
//! `api/docs/design-sealing-service-cli.md`. It opens the operating
//! Crypto-Officer session (see [`crate::provision::open_operating_session`]) —
//! replaying the full reconstruction on the `emu` flavor, or opening the
//! session directly on the `hw` flavor — then runs the `SdSealingKeyGen`
//! operation and persists the masked private-key blob and DER public key.
//!
//! The masked blob is bound to the platform identity, not to a fresh scalar the
//! host ever sees; only the masked form and the public key are written. An
//! existing sealing-key directory is never overwritten.

use azihsm_api::HsmKeyClass;
use azihsm_api::HsmKeyCommonProps;
use azihsm_api::HsmKeyKind;
use azihsm_api::HsmKeyManager;
use azihsm_api::HsmKeyPropsBuilder;
use azihsm_api::HsmSealingKeyGenAlgo;
use azihsm_ddi_tbor_types::MASKED_SEALING_KEY_LEN;

use crate::cli::CreateSdSealingKeyArgs;
use crate::error::Error;
use crate::error::Result;
use crate::manifest;
use crate::manifest::PartitionManifest;
use crate::manifest::SealingKeyEntry;
use crate::reconstruct;
use crate::util;
use crate::workspace::Workspace;

/// Run `create_sd_sealing_key`.
pub fn run(ws: &Workspace, args: &CreateSdSealingKeyArgs) -> Result<()> {
    let partition = args.partition.as_str();
    let key_name = args.sealing_key.as_str();

    // The partition must already be initialized.
    let manifest_path = ws.partition_manifest(partition);
    if !manifest_path.exists() {
        return Err(Error::NotFound {
            what: "partition",
            path: ws.partition_dir(partition),
        });
    }
    let mut part_manifest: PartitionManifest = manifest::read(&manifest_path)?;

    // Never overwrite an existing sealing key (manifest entry or on-disk dir).
    if part_manifest
        .sealing_keys
        .iter()
        .any(|k| k.name == key_name)
    {
        return Err(Error::AlreadyExists {
            what: "sealing key",
            path: ws.partition_sealing_key_dir(partition, key_name),
        });
    }
    let key_dir = ws.partition_sealing_key_dir(partition, key_name);
    if key_dir.exists() {
        return Err(Error::AlreadyExists {
            what: "sealing key directory",
            path: key_dir.clone(),
        });
    }

    // Open the operating session (emu reconstructs; hw opens directly).
    let operating = reconstruct::open(ws, &part_manifest)?;

    // Generate the sealing key: a P-384 `Sealing` secret permitted for
    // derivation only, matching the `SdSealingKeyGen` wire contract.
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Sealing)
        .bits(384)
        .can_derive(true)
        .build()
        .map_err(|e| Error::hsm("build_key_props", format!("{e:?}")))?;
    let mut algo = HsmSealingKeyGenAlgo::default();
    let key = HsmKeyManager::generate_key(&operating.session, &mut algo, props)
        .map_err(|e| Error::hsm("generate_key", format!("{e:?}")))?;

    let masked = key
        .masked_key_vec()
        .map_err(|e| Error::hsm("masked_key_vec", format!("{e:?}")))?;
    if masked.len() != MASKED_SEALING_KEY_LEN {
        return Err(Error::hsm(
            "masked_key_vec",
            format!(
                "masked sealing key must be {MASKED_SEALING_KEY_LEN} bytes, got {}",
                masked.len()
            ),
        ));
    }
    let pub_der = key
        .pub_key_der_vec()
        .map_err(|e| Error::hsm("pub_key_der_vec", format!("{e:?}")))?;
    if pub_der.is_empty() {
        return Err(Error::hsm("pub_key_der_vec", "public key DER is empty"));
    }

    // Persist the key material and append the manifest entry.
    util::create_dir_all(&key_dir)?;
    let masked_path = ws.partition_sealing_key_masked(partition, key_name);
    let pub_path = ws.partition_sealing_key_public(partition, key_name);
    util::write_secret(&masked_path, &masked)?;
    util::write_atomic(&pub_path, &pub_der)?;

    let public_key_sha384 = util::sha384_hex(&pub_der);
    part_manifest.sealing_keys.push(SealingKeyEntry {
        name: key_name.to_owned(),
        masked_key: rel(ws, &masked_path)?,
        public_key: rel(ws, &pub_path)?,
        public_key_sha384: public_key_sha384.clone(),
        reports: Vec::new(),
    });
    manifest::write(&manifest_path, &part_manifest)?;

    print_summary(partition, key_name, &public_key_sha384);
    Ok(())
}

fn print_summary(partition: &str, key_name: &str, public_key_sha384: &str) {
    println!("create_sd_sealing_key: generated `{key_name}` on `{partition}`");
    println!("  public key sha384: {public_key_sha384}");
    println!("  flavor:            {}", crate::flavor::FLAVOR);
}

fn rel(ws: &Workspace, abs: &std::path::Path) -> Result<String> {
    ws.relative(abs)
        .map_err(|err| Error::Internal(err.to_string()))
}
