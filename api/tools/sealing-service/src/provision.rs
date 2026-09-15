// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Partition provisioning and reconstruction against the HSM backend.
//!
//! Drives the security-domain provisioning sequence through the public
//! `azihsm_api` surface, mirroring `finalized_co_session` /
//! `provision_backing_ex` in `api/tests/src/utils/sd_provision.rs`:
//!
//! 1. open the backend partition and factory-reset it;
//! 2. bootstrap a Crypto-Officer session under the default PSK and
//!    `change_psk` to a rotated PSK, then close the bootstrap session;
//! 3. reopen under the rotated PSK;
//! 4. read the PID and PID public key;
//! 5. `part_init_ex` with the machine seed and policy;
//! 6. build a POTA-anchored PTA chain from the returned CSR and
//!    `part_final_ex` to reach the `Initialized` state.
//!
//! [`provision_partition`] runs the one-time initial provisioning for
//! `create_partition`. [`open_operating_session`] prepares the operating
//! session that every later command needs: on the `emu` flavor it replays the
//! full reconstruction (reset, session setup, `part_init_ex`, and
//! `part_final_ex` with the persisted previous local-MK backup); on the `hw`
//! flavor it simply opens the Crypto-Officer session on the already-initialized
//! device.

use azihsm_api::HsmApiRev;
use azihsm_api::HsmCert;
use azihsm_api::HsmPartition;
use azihsm_api::HsmPartitionManager;
use azihsm_api::HsmPskId;
use azihsm_api::HsmSession;
use azihsm_api::HsmSessionExType;
use azihsm_api::HsmSessionPsk;
use azihsm_api::PSK_LEN;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;

use crate::authority::AuthoritySet;
use crate::crypto::certs;
use crate::crypto::certs::RAW_PUB_LEN;
use crate::crypto::policy;
use crate::crypto::policy::BACKUP_PART_ID_LEN;
use crate::error::Error;
use crate::error::Result;

/// A fixed non-default CO PSK used to clear the default-PSK gate.
const ROTATED_CO_PSK: [u8; PSK_LEN] = [
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
    0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
];

/// The result of provisioning one partition.
pub struct Provisioned {
    /// The partition identifier (16 bytes).
    pub pid: Vec<u8>,
    /// The partition-identity public key (raw `X ‖ Y`, 96 bytes).
    pub pid_pub: [u8; RAW_PUB_LEN],
    /// The exact policy image used by `part_init_ex` / `part_final_ex`.
    pub policy: [u8; PART_POLICY_LEN],
    /// The rotated Crypto-Officer PSK the workspace must present henceforth.
    pub co_psk: [u8; PSK_LEN],
    /// The machine seed supplied to `part_init_ex`.
    pub mach_seed: [u8; MACH_SEED_LEN],
    /// The `local_mk_backup` returned by `part_final_ex`.
    pub local_mk_backup: Vec<u8>,
}

/// An operating session ready to run a secure-domain operation.
pub struct Operating {
    /// The open Crypto-Officer session bound to the partition.
    pub session: HsmSession,
    /// `Some` on the `emu` flavor: the freshly returned `local_mk_backup` from
    /// the reconstruction's `part_final_ex`, which must atomically replace the
    /// persisted recovery backup. `None` on the `hw` flavor, which never
    /// replays reconstruction.
    pub new_local_mk_backup: Option<Vec<u8>>,
}

/// Open the sole backend partition and factory-reset it.
fn open_and_reset() -> Result<(HsmPartition, HsmApiRev)> {
    let info = HsmPartitionManager::partition_info_list()
        .into_iter()
        .next()
        .ok_or_else(|| Error::hsm("open_partition", "backend advertised no partition"))?;
    let rev = info
        .api_rev_range
        .ok_or_else(|| Error::hsm("open_partition", "partition reported no api-rev range"))?
        .max();
    let part = HsmPartitionManager::open_partition(&info.path, rev)
        .map_err(|e| Error::hsm("open_partition", format!("{e:?}")))?;
    part.reset()
        .map_err(|e| Error::hsm("reset", format!("{e:?}")))?;
    Ok((part, rev))
}

/// Bootstrap the Crypto-Officer session under the default PSK, rotate it to
/// `co_psk`, then reopen and return the session under the rotated PSK.
fn open_rotated_session(
    part: &HsmPartition,
    rev: HsmApiRev,
    co_psk: &[u8; PSK_LEN],
) -> Result<HsmSession> {
    // Bootstrap the CO session under the default PSK and rotate it; the
    // bootstrap session closes on drop at the end of this block.
    {
        let bootstrap = part
            .open_session_ex(
                rev,
                HsmSessionPsk::new(HsmPskId::CO),
                HsmSessionExType::Authenticated,
            )
            .map_err(|e| Error::hsm("open_session_ex(bootstrap)", format!("{e:?}")))?;
        bootstrap
            .change_psk(co_psk)
            .map_err(|e| Error::hsm("change_psk", format!("{e:?}")))?;
    }

    part.open_session_ex(
        rev,
        HsmSessionPsk::with_psk(HsmPskId::CO, co_psk),
        HsmSessionExType::Authenticated,
    )
    .map_err(|e| Error::hsm("open_session_ex(rotated)", format!("{e:?}")))
}

/// Read and length-check the PID and PID public key from an open partition.
fn read_identity(part: &HsmPartition) -> Result<(Vec<u8>, [u8; RAW_PUB_LEN])> {
    let pid = part
        .pid()
        .map_err(|e| Error::hsm("pid", format!("{e:?}")))?;
    let pid_pub_vec = part
        .ex_pub_key()
        .map_err(|e| Error::hsm("ex_pub_key", format!("{e:?}")))?;
    if pid.len() != BACKUP_PART_ID_LEN {
        return Err(Error::hsm(
            "pid",
            format!("PID must be {BACKUP_PART_ID_LEN} bytes, got {}", pid.len()),
        ));
    }
    if pid_pub_vec.len() != RAW_PUB_LEN {
        return Err(Error::hsm(
            "ex_pub_key",
            format!(
                "PID public key must be {RAW_PUB_LEN} bytes, got {}",
                pid_pub_vec.len()
            ),
        ));
    }
    let mut pid_pub = [0u8; RAW_PUB_LEN];
    pid_pub.copy_from_slice(&pid_pub_vec);
    Ok((pid, pid_pub))
}

/// Run `part_init_ex` + `part_final_ex` on `session`, building the
/// POTA-anchored PTA chain from the returned CSR. `prev_local_mk` is `None` for
/// initial provisioning and `Some` for emulator reconstruction. Returns the
/// `local_mk_backup` that `part_final_ex` produced.
fn init_and_finalize(
    session: &HsmSession,
    authset: &AuthoritySet,
    policy: &[u8; PART_POLICY_LEN],
    mach_seed: &[u8; MACH_SEED_LEN],
    prev_local_mk: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let init = session
        .part_init_ex(
            mach_seed,
            policy,
            &policy::pota_thumbprint(),
            &policy::sata_thumbprint(),
            None,
        )
        .map_err(|e| Error::hsm("part_init_ex", format!("{e:?}")))?;

    let pta_pub = certs::pta_pub_from_csr(&init.pta_csr)?;
    let chain = certs::make_pta_chain(&authset.pota, &pta_pub);
    let certs = [
        HsmCert {
            cert: &chain.root_der,
        },
        HsmCert {
            cert: &chain.pta_der,
        },
    ];
    let result = session
        .part_final_ex(policy, &certs, prev_local_mk)
        .map_err(|e| Error::hsm("part_final_ex", format!("{e:?}")))?;
    Ok(result.local_mk_backup)
}

/// Provision a fresh partition anchored to `authset`.
///
/// When `policy_override` is `None`, a backing-partition policy is built from
/// this partition's identity and the authority set's SATA/POTA anchors. When
/// it is `Some`, the supplied policy is used verbatim (the additional-partition
/// reuse path). In both cases the authority set's POTA key signs the PTA chain.
pub fn provision_partition(
    authset: &AuthoritySet,
    policy_override: Option<[u8; PART_POLICY_LEN]>,
) -> Result<Provisioned> {
    let (part, rev) = open_and_reset()?;
    let session = open_rotated_session(&part, rev, &ROTATED_CO_PSK)?;

    let (pid, pid_pub) = read_identity(&part)?;

    let policy = match policy_override {
        Some(policy) => policy,
        None => policy::backing_part_policy(
            &pid,
            &pid_pub,
            &authset.sata.raw_pub(),
            &authset.pota.raw_pub(),
            true,
        )?,
    };

    let mach_seed = policy::mach_seed();
    let local_mk_backup = init_and_finalize(&session, authset, &policy, &mach_seed, None)?;

    Ok(Provisioned {
        pid,
        pid_pub,
        policy,
        co_psk: ROTATED_CO_PSK,
        mach_seed,
        local_mk_backup,
    })
}

/// Prepare the operating Crypto-Officer session for a later command.
///
/// On the `emu` flavor this replays the full reconstruction against the
/// transient emulator partition — reset, rotated-PSK session setup,
/// `part_init_ex` with the persisted machine seed and policy, and
/// `part_final_ex` restoring the persisted previous local-MK backup — and
/// returns the newly produced backup so the caller can replace the persisted
/// one. On the `hw` flavor it opens the Crypto-Officer session on the
/// already-initialized device and performs no reconstruction.
#[cfg(feature = "emu")]
pub fn open_operating_session(
    authset: &AuthoritySet,
    policy: &[u8; PART_POLICY_LEN],
    co_psk: &[u8; PSK_LEN],
    mach_seed: &[u8; MACH_SEED_LEN],
    prev_local_mk: &[u8],
    identity: &[u8],
) -> Result<Operating> {
    let (part, rev) = open_and_reset()?;
    let session = open_rotated_session(&part, rev, co_psk)?;
    let new_local_mk_backup =
        init_and_finalize(&session, authset, policy, mach_seed, Some(prev_local_mk))?;
    // Re-inject the captured identity as the final reconstruction step: the
    // reset above re-randomized the emulator keypair, so this must run after
    // `part_init_ex` / `part_final_ex` (which bind policy but never touch the
    // identity) to leave the identity byte-stable across processes.
    inject_identity(identity)?;
    Ok(Operating {
        session,
        new_local_mk_backup: Some(new_local_mk_backup),
    })
}

/// Prepare the operating Crypto-Officer session for a later command.
///
/// On the `hw` flavor the initialized partition and its local masking key
/// persist on the device, so this simply opens the Crypto-Officer session under
/// the persisted rotated PSK; it never resets, rotates, or replays
/// `part_init_ex` / `part_final_ex`.
#[cfg(not(feature = "emu"))]
pub fn open_operating_session(
    _authset: &AuthoritySet,
    _policy: &[u8; PART_POLICY_LEN],
    co_psk: &[u8; PSK_LEN],
    _mach_seed: &[u8; MACH_SEED_LEN],
    _prev_local_mk: &[u8],
    _identity: &[u8],
) -> Result<Operating> {
    let info = HsmPartitionManager::partition_info_list()
        .into_iter()
        .next()
        .ok_or_else(|| Error::hsm("open_partition", "backend advertised no partition"))?;
    let rev = info
        .api_rev_range
        .ok_or_else(|| Error::hsm("open_partition", "partition reported no api-rev range"))?
        .max();
    let part = HsmPartitionManager::open_partition(&info.path, rev)
        .map_err(|e| Error::hsm("open_partition", format!("{e:?}")))?;
    let session = part
        .open_session_ex(
            rev,
            HsmSessionPsk::with_psk(HsmPskId::CO, co_psk),
            HsmSessionExType::Authenticated,
        )
        .map_err(|e| Error::hsm("open_session_ex(rotated)", format!("{e:?}")))?;
    Ok(Operating {
        session,
        new_local_mk_backup: None,
    })
}

/// Capture the emulator partition's live cryptographic identity as a flat byte
/// image (`PID ‖ identity pub key ‖ identity private scalar`).
///
/// Emulator-only scaffolding used by `create_partition` to persist the identity
/// so later commands can re-inject it and keep it byte-stable across separate
/// processes, mirroring hardware where the identity is retained on the device.
#[cfg(feature = "emu")]
pub fn export_identity() -> Result<Vec<u8>> {
    let ident = azihsm_ddi_emu::emu_export_identity()
        .map_err(|e| Error::hsm("emu_export_identity", format!("{e:?}")))?;
    let mut out =
        Vec::with_capacity(ident.id().len() + ident.id_pub().len() + ident.id_priv().len());
    out.extend_from_slice(ident.id());
    out.extend_from_slice(ident.id_pub());
    out.extend_from_slice(ident.id_priv());
    Ok(out)
}

/// Hardware stub — never reached (the emulator recovery block is guarded by a
/// runtime `cfg!(feature = "emu")` check), present only so the shared
/// `create_partition` code path compiles on the `hw` flavor.
#[cfg(not(feature = "emu"))]
pub fn export_identity() -> Result<Vec<u8>> {
    Err(Error::Internal(
        "export_identity is emulator-only".to_owned(),
    ))
}

/// Re-inject a previously captured identity image into the emulator partition.
///
/// Splits the flat image back into `PID ‖ identity pub key ‖ identity private
/// scalar` and restores it, overwriting the freshly randomized emulator
/// identity produced by the reconstruction reset.
#[cfg(feature = "emu")]
fn inject_identity(bytes: &[u8]) -> Result<()> {
    let header = BACKUP_PART_ID_LEN + RAW_PUB_LEN;
    if bytes.len() <= header {
        return Err(Error::hsm(
            "inject_identity",
            format!("identity image too short: {} bytes", bytes.len()),
        ));
    }
    let (id, rest) = bytes.split_at(BACKUP_PART_ID_LEN);
    let (id_pub, id_priv) = rest.split_at(RAW_PUB_LEN);
    let ident = azihsm_ddi_emu::PartIdentity::from_parts(id, id_pub, id_priv)
        .map_err(|e| Error::hsm("PartIdentity::from_parts", format!("{e:?}")))?;
    azihsm_ddi_emu::emu_inject_identity(ident)
        .map_err(|e| Error::hsm("emu_inject_identity", format!("{e:?}")))?;
    Ok(())
}
