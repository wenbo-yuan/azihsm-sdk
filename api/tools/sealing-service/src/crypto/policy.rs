// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Partition-policy assembly and field extraction.
//!
//! Ported from the policy helpers in `api/tests/src/utils/sd_provision.rs`.
//! Builds the unified `PartPolicy` image that names the backing partition and
//! anchors the domain to the authority set's SATA and POTA keys, and reads the
//! SATA/POTA public keys back out of a policy image for reuse-mode validation.

use azihsm_api::PartPolicyBuilder;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POLICY_INFO_LEN;
use azihsm_ddi_tbor_types::POLICY_MAX_KEY_LEN;
use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::PolicyKeyKind;
use azihsm_ddi_tbor_types::PolicyPubKey;
use azihsm_ddi_tbor_types::SATA_THUMBPRINT_LEN;
use zerocopy::IntoBytes;

use crate::crypto::certs::RAW_PUB_LEN;
use crate::error::Error;
use crate::error::Result;

/// Length of the backing-partition identifier (PID).
pub const BACKUP_PART_ID_LEN: usize = 16;

/// Build a policy naming **this** partition as the backing partition
/// (`backup_part_id = PID`, `backup_part_pub_key = PID public key`) and
/// anchoring the security domain to `sata_pub` and `pota_pub` (raw `X ‖ Y`).
///
/// Uses the typed [`PartPolicyBuilder`] so the produced wire image matches
/// exactly what the firmware expects (named fields, correct key-kind / length
/// discriminants), rather than hand-poking raw byte offsets.
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

    let policy = PartPolicyBuilder::new()
        .version(1, 0)
        .pota_key(PolicyKeyKind::Ecc384, pota_pub)
        .sata_key(PolicyKeyKind::Ecc384, sata_pub)
        .backup_part_id(pid)
        .backup_part_pub_key(PolicyKeyKind::Ecc384, pid_pub)
        .info(&[0xAB; POLICY_INFO_LEN])
        .allow_peer_cloning(allow_peer_cloning)
        .build()
        .map_err(|e| Error::Internal(format!("failed to build PartPolicy: {e:?}")))?;

    let mut bytes = [0u8; PART_POLICY_LEN];
    bytes.copy_from_slice(policy.as_bytes());
    Ok(bytes)
}

/// Read the raw `X ‖ Y` POTA public key out of a policy image.
pub fn pota_raw_from_policy(policy: &[u8]) -> Result<[u8; RAW_PUB_LEN]> {
    raw_pub_from(policy, |p| &p.pota_pub_key)
}

/// Read the raw `X ‖ Y` SATA public key out of a policy image.
pub fn sata_raw_from_policy(policy: &[u8]) -> Result<[u8; RAW_PUB_LEN]> {
    raw_pub_from(policy, |p| &p.sata_pub_key)
}

/// Extract the raw `X ‖ Y` coordinates of a selected [`PolicyPubKey`] from a
/// policy image via a typed zero-copy view (robust to layout changes).
fn raw_pub_from(
    policy: &[u8],
    select: impl Fn(&PartPolicy) -> &PolicyPubKey,
) -> Result<[u8; RAW_PUB_LEN]> {
    let typed = PartPolicy::ref_from_wire(policy).ok_or_else(|| {
        Error::PolicyMismatch("policy image is not a valid PartPolicy".to_owned())
    })?;
    let mut raw = [0u8; RAW_PUB_LEN];
    raw.copy_from_slice(&select(typed).data[..RAW_PUB_LEN]);
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
