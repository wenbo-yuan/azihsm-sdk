// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Partition-policy assembly and field extraction.
//!
//! Ported from the policy helpers in `api/tests/src/utils/sd_provision.rs`.
//! Builds the unified `PartPolicy` image that names the backing partition and
//! anchors the domain to the authority set's SATA and POTA keys, and reads the
//! SATA/POTA public keys back out of a policy image for reuse-mode validation.

use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POLICY_INFO_LEN;
use azihsm_ddi_tbor_types::POLICY_MAX_KEY_LEN;
use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::PolicyFlags;
use azihsm_ddi_tbor_types::PolicyKeyKind;
use azihsm_ddi_tbor_types::PolicyPubKey;
use azihsm_ddi_tbor_types::PolicyVer;
use azihsm_ddi_tbor_types::SATA_THUMBPRINT_LEN;
use zerocopy::IntoBytes;

use crate::crypto::certs::RAW_PUB_LEN;
use crate::error::Error;
use crate::error::Result;

/// Byte offset of the POTA public-key **data** inside the `PartPolicy` image:
/// `pota_pub_key` starts at 2 (`version(2)`), and its raw `X ‖ Y` coordinates
/// begin at 6 (`kind(2) ‖ len(2)`).
const OFF_POTA_PUB_KEY_DATA: usize = 6;

/// Byte offset of the SATA public-key **data** inside the `PartPolicy` image
/// (`pota_pub_key` occupies 100 bytes, so `sata_pub_key` data begins at 106).
const OFF_SATA_PUB_KEY_DATA: usize = 106;

/// Byte offset of `backup_part_id` inside the `PartPolicy` image.
const OFF_BACKUP_PART_ID: usize = 302;

/// Byte offset of `backup_part_pub_key` inside the `PartPolicy` image.
const OFF_BACKUP_PART_PUB_KEY: usize = 318;

/// Length of the backing-partition identifier (PID).
pub const BACKUP_PART_ID_LEN: usize = 16;

/// Build a unified `PartPolicy` binding the real POTA public key so
/// `part_final_ex` can validate a chain anchored to it. SATA carries a filler
/// key that the caller overwrites with the real anchor coordinates.
fn part_policy_with_pota(pota_raw: &[u8; RAW_PUB_LEN], allow_peer_cloning: bool) -> PartPolicy {
    let mut sata = [0u8; POLICY_MAX_KEY_LEN];
    for (i, b) in sata.iter_mut().enumerate() {
        *b = (0x20u8.wrapping_add(i as u8)) | 0x80;
    }
    PartPolicy {
        version: PolicyVer { major: 1, minor: 0 },
        pota_pub_key: PolicyPubKey::new(PolicyKeyKind::Ecc384, RAW_PUB_LEN as u16, *pota_raw),
        sata_pub_key: PolicyPubKey::new(PolicyKeyKind::Ecc384, RAW_PUB_LEN as u16, sata),
        info: [0xAB; POLICY_INFO_LEN],
        flags: PolicyFlags::new().with_allow_peer_cloning(allow_peer_cloning),
        ..PartPolicy::zeroed()
    }
}

/// Build a policy naming **this** partition as the backing partition
/// (`backup_part_id = PID`, `backup_part_pub_key = PID public key`) and
/// anchoring the security domain to `sata_pub` and `pota_pub` (raw `X ‖ Y`).
pub fn backing_part_policy(
    pid: &[u8],
    pid_pub: &[u8],
    sata_pub: &[u8; RAW_PUB_LEN],
    pota_pub: &[u8; RAW_PUB_LEN],
    allow_peer_cloning: bool,
) -> Result<[u8; PART_POLICY_LEN]> {
    if pid.len() != BACKUP_PART_ID_LEN {
        return Err(Error::Internal(format!(
            "PID must be {BACKUP_PART_ID_LEN} bytes, got {}",
            pid.len()
        )));
    }
    if pid_pub.len() != POLICY_MAX_KEY_LEN {
        return Err(Error::Internal(format!(
            "PID public key must be {POLICY_MAX_KEY_LEN} bytes, got {}",
            pid_pub.len()
        )));
    }

    let policy = part_policy_with_pota(pota_pub, allow_peer_cloning);
    let mut bytes = [0u8; PART_POLICY_LEN];
    bytes.copy_from_slice(policy.as_bytes());

    // Overwrite the placeholder SATA key with the anchor's real P-384
    // coordinates (kind / len already Ecc384 / 96).
    bytes[OFF_SATA_PUB_KEY_DATA..OFF_SATA_PUB_KEY_DATA + RAW_PUB_LEN].copy_from_slice(sata_pub);

    bytes[OFF_BACKUP_PART_ID..OFF_BACKUP_PART_ID + BACKUP_PART_ID_LEN].copy_from_slice(pid);

    // backup_part_pub_key = { kind: Ecc384 (LE), len: 96 (LE), data }.
    let off = OFF_BACKUP_PART_PUB_KEY;
    bytes[off..off + 2].copy_from_slice(&PolicyKeyKind::Ecc384.0.to_le_bytes());
    bytes[off + 2..off + 4].copy_from_slice(&(POLICY_MAX_KEY_LEN as u16).to_le_bytes());
    bytes[off + 4..off + 4 + POLICY_MAX_KEY_LEN].copy_from_slice(pid_pub);

    Ok(bytes)
}

/// Read the raw `X ‖ Y` POTA public key out of a policy image.
pub fn pota_raw_from_policy(policy: &[u8]) -> Result<[u8; RAW_PUB_LEN]> {
    raw_pub_at(policy, OFF_POTA_PUB_KEY_DATA)
}

/// Read the raw `X ‖ Y` SATA public key out of a policy image.
pub fn sata_raw_from_policy(policy: &[u8]) -> Result<[u8; RAW_PUB_LEN]> {
    raw_pub_at(policy, OFF_SATA_PUB_KEY_DATA)
}

fn raw_pub_at(policy: &[u8], offset: usize) -> Result<[u8; RAW_PUB_LEN]> {
    let slice = policy
        .get(offset..offset + RAW_PUB_LEN)
        .ok_or_else(|| Error::PolicyMismatch("policy image is too short".to_owned()))?;
    let mut raw = [0u8; RAW_PUB_LEN];
    raw.copy_from_slice(slice);
    Ok(raw)
}

/// Deterministic machine-seed fixture.
pub fn mach_seed() -> [u8; MACH_SEED_LEN] {
    let mut v = [0u8; MACH_SEED_LEN];
    for (i, b) in v.iter_mut().enumerate() {
        *b = 0x40u8.wrapping_add(i as u8);
    }
    v
}

/// Deterministic POTA thumbprint fixture (stored, not chain-validated).
pub fn pota_thumbprint() -> [u8; POTA_THUMBPRINT_LEN] {
    let mut v = [0u8; POTA_THUMBPRINT_LEN];
    for (i, b) in v.iter_mut().enumerate() {
        *b = 0x80 ^ i as u8;
    }
    v
}

/// Deterministic SATA thumbprint fixture (stored, not chain-validated).
pub fn sata_thumbprint() -> [u8; SATA_THUMBPRINT_LEN] {
    let mut v = [0u8; SATA_THUMBPRINT_LEN];
    for (i, b) in v.iter_mut().enumerate() {
        *b = 0x40 ^ i as u8;
    }
    v
}
