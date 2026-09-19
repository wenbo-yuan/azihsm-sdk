// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! JSON manifest models.
//!
//! These serialize to the schemas defined in the "Manifest schemas" section of
//! `api/docs/design-sealing-service-cli.md`. Every manifest is a single
//! top-level JSON object with `schema_version` `1` and a `kind` tag; all path
//! values are POSIX and relative to the workspace root; digests are 96-character
//! lowercase-hex SHA-384; timestamps are RFC 3339 UTC with a `Z` suffix.
//!
//! A secure domain is a single BKS3 (root key material), not a version
//! history, so artifacts are role-named and addressed by member or destination
//! partition — there is no generation model.

use std::path::Path;

use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::Error;
use crate::error::Result;
use crate::util;

/// The current manifest `schema_version`.
pub const SCHEMA_VERSION: u32 = 1;

/// A named file reference with its expected SHA-384 digest (lowercase hex).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRef {
    /// Working-dir-relative POSIX path.
    pub path: String,
    /// 96-character lowercase-hex SHA-384 digest of the referenced bytes.
    pub sha384: String,
}

/// A file inside a member area, named without a directory prefix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedArtifact {
    /// File name (for example `pok-local-backup.bin`).
    pub name: String,
    /// Byte length of the file.
    pub length: u64,
    /// 96-character lowercase-hex SHA-384 digest.
    pub sha384: String,
}

/// A partition's role within a secure domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// The single partition named by the policy's `backup_part_id`; the only
    /// partition allowed to run `create_remote_backup` for the domain.
    Backing,
    /// A partition that joined later via a restore and holds the same BKS3.
    Member,
}

/// The kind of outbound hand-off backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HandoffKind {
    /// A remote backup produced by `create_remote_backup` or `reseal_remote_backup`.
    Remote,
    /// A peer backup produced by `create_peer_backup`.
    Peer,
}

/// Scope of a secure domain's first backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackupScope {
    /// Backing and receiver are the same partition.
    #[serde(rename = "self")]
    SelfBackup,
    /// The domain was created for a distinct receiver partition.
    CrossPartition,
}

// ---------------------------------------------------------------------------
// authority-set.json
// ---------------------------------------------------------------------------

/// `authority-set.json` — one authority set and its single backing policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthoritySetManifest {
    pub schema_version: u32,
    pub kind: String,
    pub name: String,
    pub created_utc: String,
    pub algorithm: String,
    pub curve: String,
    pub authorities: Authorities,
    pub certificate_rules: CertificateRules,
    pub backing_policy: FileRef,
}

/// The four (plus optional secondary POTA) authorities of an authority set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authorities {
    pub manufacturer: Authority,
    pub owner: Authority,
    pub sata: Authority,
    pub pota: Authority,
    #[serde(default)]
    pub sapota: Option<Authority>,
}

/// One authority's public root certificate and private key references.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authority {
    pub root_cert: String,
    pub private_key: String,
    pub public_key_sha384: String,
    pub root_cert_sha384: String,
}

/// Certificate-issuance rules governing every certificate an authority set
/// issues.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRules {
    pub subject_template: String,
    pub serial_method: String,
    pub validity: Validity,
}

/// Certificate validity window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validity {
    pub not_before: String,
    pub duration_days: u32,
}

// ---------------------------------------------------------------------------
// partition.json
// ---------------------------------------------------------------------------

/// `partition.json` — one logical partition's identity and named keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionManifest {
    pub schema_version: u32,
    pub kind: String,
    pub name: String,
    pub created_utc: String,
    pub pid: String,
    pub pid_public_key: FileRef,
    pub authority_set: String,
    pub backing_policy: FileRef,
    pub session: Session,
    /// Present only for the `emu` flavor; `null` on `hw`.
    pub recovery: Option<PartitionRecovery>,
    pub attestation: Attestation,
    pub sealing_keys: Vec<SealingKeyEntry>,
    /// Name of the one domain this partition belongs to, or `null`.
    pub secure_domain: Option<String>,
}

/// Session credential binding for a partition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub co_psk: String,
    pub psk_rotated: bool,
}

/// Emulator-only recovery material used to replay a partition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionRecovery {
    pub mach_seed: String,
    pub part_final_local_mk_backup: String,
    /// Captured partition identity (PID ‖ identity pub key ‖ identity private
    /// scalar), re-injected on every emulator reconstruction to keep the
    /// identity byte-stable across processes.
    pub identity: String,
}

/// A partition's attestation authority roots and three PID chains.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub authorities: AttestationAuthorities,
    pub manufacturer_chain: Vec<String>,
    pub owner_chain: Vec<String>,
    pub partition_owner_chain: Vec<String>,
}

/// The public authority roots copied into a partition's attestation area.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationAuthorities {
    pub manufacturer_root: String,
    pub owner_root: String,
    pub sata_root: String,
}

/// One named sealing key and its evidence bundles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealingKeyEntry {
    pub name: String,
    pub masked_key: String,
    pub public_key: String,
    pub public_key_sha384: String,
    pub reports: Vec<String>,
}

// ---------------------------------------------------------------------------
// secure-domain.json
// ---------------------------------------------------------------------------

/// `secure-domain.json` — domain identity, members, and hand-off lineage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureDomainManifest {
    pub schema_version: u32,
    pub kind: String,
    pub name: String,
    pub created_utc: String,
    pub authority_set: String,
    pub policy: FileRef,
    pub backing_partition: PartitionRef,
    pub backup_scope: BackupScope,
    pub members: Vec<DomainMember>,
    pub handoffs: Vec<Handoff>,
}

/// A partition named by workspace name and PID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionRef {
    pub name: String,
    pub pid: String,
}

/// A member entry in `secure-domain.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainMember {
    pub partition: String,
    pub pid: String,
    pub role: Role,
    pub joined_via: String,
    pub source_partition: Option<String>,
    pub created_utc: String,
}

/// An outbound hand-off entry in `secure-domain.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handoff {
    pub kind: HandoffKind,
    pub destination: String,
    pub pid: String,
    pub sealing_key_sha384: String,
    pub evidence_ref: String,
    pub evidence_sha384: String,
    pub artifact: String,
    pub created_by: String,
    pub source_partition: String,
    pub consumed: bool,
}

// ---------------------------------------------------------------------------
// member.json
// ---------------------------------------------------------------------------

/// `member.json` — one partition's copy of the domain's BKS3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberManifest {
    pub schema_version: u32,
    pub kind: String,
    pub partition: String,
    pub pid: String,
    pub role: Role,
    pub joined_via: String,
    pub source_partition: Option<String>,
    pub source_handoff: Option<String>,
    pub created_utc: String,
    pub updated_utc: String,
    pub artifacts: Vec<NamedArtifact>,
}

// ---------------------------------------------------------------------------
// Read / write helpers
// ---------------------------------------------------------------------------

/// A manifest type that can be read back with `schema_version` and `kind`
/// validation.
pub trait Manifest: Serialize + DeserializeOwned {
    /// The `kind` tag string this manifest uses.
    const KIND: &'static str;

    /// The declared `schema_version`.
    fn schema_version(&self) -> u32;

    /// The declared `kind`.
    fn kind(&self) -> &str;
}

/// Serialize `manifest` as pretty JSON and atomically write it to `path`.
pub fn write<M: Manifest>(path: &Path, manifest: &M) -> Result<()> {
    let json = serde_json::to_vec_pretty(manifest).map_err(|source| Error::Manifest {
        path: path.to_path_buf(),
        detail: format!("serialize: {source}"),
    })?;
    util::write_atomic(path, &json)
}

/// Read a manifest from `path`, rejecting an unknown `schema_version` or a
/// `kind` mismatch.
pub fn read<M: Manifest>(path: &Path) -> Result<M> {
    let bytes = util::read_file(path)?;
    let manifest: M = serde_json::from_slice(&bytes).map_err(|source| Error::Manifest {
        path: path.to_path_buf(),
        detail: format!("parse: {source}"),
    })?;
    if manifest.schema_version() != SCHEMA_VERSION {
        return Err(Error::Manifest {
            path: path.to_path_buf(),
            detail: format!("unsupported schema_version {}", manifest.schema_version()),
        });
    }
    if manifest.kind() != M::KIND {
        return Err(Error::Manifest {
            path: path.to_path_buf(),
            detail: format!("expected kind `{}`, found `{}`", M::KIND, manifest.kind()),
        });
    }
    Ok(manifest)
}

macro_rules! impl_manifest {
    ($ty:ty, $kind:literal) => {
        impl Manifest for $ty {
            const KIND: &'static str = $kind;
            fn schema_version(&self) -> u32 {
                self.schema_version
            }
            fn kind(&self) -> &str {
                &self.kind
            }
        }
    };
}

impl_manifest!(AuthoritySetManifest, "authority-set");
impl_manifest!(PartitionManifest, "partition");
impl_manifest!(SecureDomainManifest, "secure-domain");
impl_manifest!(MemberManifest, "member");
