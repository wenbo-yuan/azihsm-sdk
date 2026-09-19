// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared partition-reconstruction helper.
//!
//! Every command that operates on an initialized partition
//! (`create_sd_sealing_key`, `key_report`, `create_sd`, the restore/reseal/peer
//! flows) first opens the operating Crypto-Officer session. On the `emu` flavor
//! that replays the full reconstruction (reset, rotated-PSK session setup,
//! `part_init_ex` / `part_final_ex` with the persisted recovery material, and
//! emulator identity injection); on the `hw` flavor it opens the session
//! directly on the already-initialized device. This module centralizes that
//! setup — loading the manifest-referenced inputs, opening the session, and
//! persisting the refreshed emulator recovery backup — so the command handlers
//! only run their own HSM operation.

use azihsm_api::PSK_LEN;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;

use crate::authority::AuthoritySet;
use crate::error::Error;
use crate::error::Result;
use crate::manifest::PartitionManifest;
use crate::provision;
use crate::provision::Operating;
use crate::util;
use crate::workspace::Workspace;

/// Open the operating Crypto-Officer session for an initialized partition.
///
/// On the `emu` flavor this reconstructs the transient partition from the
/// manifest-recorded recovery material and atomically replaces the persisted
/// `part_final` local-MK backup with the freshly produced one before returning.
/// On the `hw` flavor it opens the session directly. The returned [`Operating`]
/// carries the live session the caller runs its operation on.
pub fn open(ws: &Workspace, part_manifest: &PartitionManifest) -> Result<Operating> {
    let partition = part_manifest.name.as_str();

    // Reconstruction inputs. The authority set signs the PTA chain the
    // emulator replay rebuilds; the policy and CO PSK are recorded in the
    // partition manifest and shared by both flavors.
    let authset = AuthoritySet::load(ws, &part_manifest.authority_set)?;
    let co_psk = load_co_psk(ws, part_manifest)?;
    let policy = load_policy(ws, part_manifest)?;

    // Emulator recovery material — replayed to rebuild the transient partition.
    // On the `hw` flavor the partition persists on the device, so these inputs
    // are ignored and passed as empty placeholders.
    let (mach_seed, prev_local_mk, identity) = if cfg!(feature = "emu") {
        let recovery = part_manifest.recovery.as_ref().ok_or_else(|| {
            Error::Internal("emu partition manifest is missing recovery material".to_owned())
        })?;
        let mach_seed = load_mach_seed(ws, &recovery.mach_seed)?;
        let backup = read_workspace_file(ws, &recovery.part_final_local_mk_backup)?;
        let identity = read_workspace_file(ws, &recovery.identity)?;
        (mach_seed, backup, identity)
    } else {
        ([0u8; MACH_SEED_LEN], Vec::new(), Vec::new())
    };

    let operating = provision::open_operating_session(
        &authset,
        &policy,
        &co_psk,
        &mach_seed,
        &prev_local_mk,
        &identity,
    )?;

    // On emu, the reconstruction produced a fresh local-MK backup that must
    // atomically replace the persisted one before any operation is recorded.
    if let Some(new_backup) = &operating.new_local_mk_backup {
        util::write_atomic(&ws.partition_part_final_backup(partition), new_backup)?;
    }

    Ok(operating)
}

/// Load and length-check the rotated Crypto-Officer PSK the manifest records.
fn load_co_psk(ws: &Workspace, manifest: &PartitionManifest) -> Result<[u8; PSK_LEN]> {
    let bytes = read_workspace_file(ws, &manifest.session.co_psk)?;
    if bytes.len() != PSK_LEN {
        return Err(Error::Internal(format!(
            "co-psk must be {PSK_LEN} bytes, got {}",
            bytes.len()
        )));
    }
    let mut psk = [0u8; PSK_LEN];
    psk.copy_from_slice(&bytes);
    Ok(psk)
}

/// Load and length-check the backing-partition policy the manifest references.
fn load_policy(ws: &Workspace, manifest: &PartitionManifest) -> Result<[u8; PART_POLICY_LEN]> {
    let bytes = read_workspace_file(ws, &manifest.backing_policy.path)?;
    if bytes.len() != PART_POLICY_LEN {
        return Err(Error::Internal(format!(
            "backing policy must be {PART_POLICY_LEN} bytes, got {}",
            bytes.len()
        )));
    }
    let mut policy = [0u8; PART_POLICY_LEN];
    policy.copy_from_slice(&bytes);
    Ok(policy)
}

/// Load and length-check the emulator machine seed.
fn load_mach_seed(ws: &Workspace, rel_path: &str) -> Result<[u8; MACH_SEED_LEN]> {
    let bytes = read_workspace_file(ws, rel_path)?;
    if bytes.len() != MACH_SEED_LEN {
        return Err(Error::Internal(format!(
            "mach-seed must be {MACH_SEED_LEN} bytes, got {}",
            bytes.len()
        )));
    }
    let mut seed = [0u8; MACH_SEED_LEN];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

/// Read a file named by a workspace-relative POSIX path from a manifest.
pub fn read_workspace_file(ws: &Workspace, rel_path: &str) -> Result<Vec<u8>> {
    util::read_file(&ws.root().join(rel_path))
}
