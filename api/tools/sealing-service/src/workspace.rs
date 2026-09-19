// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Workspace layout helpers.
//!
//! The layout is defined in the "Partition artifact layout" section of
//! `api/docs/design-sealing-service-cli.md`. This module resolves the
//! top-level directories and named artifact roots within the workspace root.
//! At runtime the root is a transient scratch directory that
//! [`crate::container`] unpacks the single-file state container into before a
//! command runs and repacks afterwards; handlers see an ordinary directory
//! tree and never touch the container format directly.

use std::path::Path;
use std::path::PathBuf;

/// A validated handle to a workspace root (the scratch directory the state
/// container is unpacked into for the duration of one command).
pub struct Workspace {
    root: PathBuf,
}

impl Workspace {
    /// Wrap a workspace root. Existence and permission checks are performed by
    /// the command handlers that need them.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// The workspace root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `authority-sets/` — reusable test authority sets and backing policies.
    pub fn authority_sets_dir(&self) -> PathBuf {
        self.root.join("authority-sets")
    }

    /// `partitions/` — per-partition host artifacts.
    pub fn partitions_dir(&self) -> PathBuf {
        self.root.join("partitions")
    }

    /// `secure-domains/` — per-domain policy, member areas, and hand-offs.
    pub fn secure_domains_dir(&self) -> PathBuf {
        self.root.join("secure-domains")
    }

    /// Directory for one named partition.
    pub fn partition_dir(&self, name: &str) -> PathBuf {
        self.partitions_dir().join(name)
    }

    /// Directory for one named authority set.
    pub fn authority_set_dir(&self, name: &str) -> PathBuf {
        self.authority_sets_dir().join(name)
    }

    /// Directory for one named secure domain.
    pub fn secure_domain_dir(&self, name: &str) -> PathBuf {
        self.secure_domains_dir().join(name)
    }

    // --- Authority-set subpaths ---------------------------------------------

    /// `authority-sets/<name>/authority-set.json`.
    pub fn authority_set_manifest(&self, name: &str) -> PathBuf {
        self.authority_set_dir(name).join("authority-set.json")
    }

    /// `authority-sets/<name>/policy.bin`.
    pub fn authority_set_policy(&self, name: &str) -> PathBuf {
        self.authority_set_dir(name).join("policy.bin")
    }

    /// `authority-sets/<name>/roots/`.
    pub fn authority_set_roots_dir(&self, name: &str) -> PathBuf {
        self.authority_set_dir(name).join("roots")
    }

    /// `authority-sets/<name>/secrets/`.
    pub fn authority_set_secrets_dir(&self, name: &str) -> PathBuf {
        self.authority_set_dir(name).join("secrets")
    }

    // --- Partition subpaths -------------------------------------------------

    /// `partitions/<name>/partition.json`.
    pub fn partition_manifest(&self, name: &str) -> PathBuf {
        self.partition_dir(name).join("partition.json")
    }

    /// `partitions/<name>/secrets/`.
    pub fn partition_secrets_dir(&self, name: &str) -> PathBuf {
        self.partition_dir(name).join("secrets")
    }

    /// `partitions/<name>/secrets/co-psk.bin`.
    pub fn partition_co_psk(&self, name: &str) -> PathBuf {
        self.partition_secrets_dir(name).join("co-psk.bin")
    }

    /// `partitions/<name>/recovery/`.
    pub fn partition_recovery_dir(&self, name: &str) -> PathBuf {
        self.partition_dir(name).join("recovery")
    }

    /// `partitions/<name>/recovery/mach-seed.bin`.
    pub fn partition_mach_seed(&self, name: &str) -> PathBuf {
        self.partition_recovery_dir(name).join("mach-seed.bin")
    }

    /// `partitions/<name>/recovery/part-final-local-mk-backup.bin`.
    pub fn partition_part_final_backup(&self, name: &str) -> PathBuf {
        self.partition_recovery_dir(name)
            .join("part-final-local-mk-backup.bin")
    }

    /// `partitions/<name>/recovery/identity.bin` (emulator identity injection).
    pub fn partition_identity(&self, name: &str) -> PathBuf {
        self.partition_recovery_dir(name).join("identity.bin")
    }

    /// `partitions/<name>/attestation/`.
    pub fn partition_attestation_dir(&self, name: &str) -> PathBuf {
        self.partition_dir(name).join("attestation")
    }

    /// `partitions/<name>/attestation/pid-public-key.der`.
    pub fn partition_pid_public_key(&self, name: &str) -> PathBuf {
        self.partition_attestation_dir(name)
            .join("pid-public-key.der")
    }

    /// `partitions/<name>/attestation/authorities/`.
    pub fn partition_attestation_authorities_dir(&self, name: &str) -> PathBuf {
        self.partition_attestation_dir(name).join("authorities")
    }

    /// `partitions/<name>/attestation/<chain>/` (for example
    /// `manufacturer-chain`).
    pub fn partition_attestation_chain_dir(&self, name: &str, chain: &str) -> PathBuf {
        self.partition_attestation_dir(name).join(chain)
    }

    /// `partitions/<name>/sealing-keys/`.
    pub fn partition_sealing_keys_dir(&self, name: &str) -> PathBuf {
        self.partition_dir(name).join("sealing-keys")
    }

    /// `partitions/<name>/sealing-keys/<key>/`.
    pub fn partition_sealing_key_dir(&self, name: &str, key: &str) -> PathBuf {
        self.partition_sealing_keys_dir(name).join(key)
    }

    /// `partitions/<name>/sealing-keys/<key>/masked-key.bin`.
    pub fn partition_sealing_key_masked(&self, name: &str, key: &str) -> PathBuf {
        self.partition_sealing_key_dir(name, key)
            .join("masked-key.bin")
    }

    /// `partitions/<name>/sealing-keys/<key>/public-key.der`.
    pub fn partition_sealing_key_public(&self, name: &str, key: &str) -> PathBuf {
        self.partition_sealing_key_dir(name, key)
            .join("public-key.der")
    }

    /// `partitions/<name>/sealing-keys/<key>/evidence/`.
    pub fn partition_sealing_key_evidence_dir(&self, name: &str, key: &str) -> PathBuf {
        self.partition_sealing_key_dir(name, key).join("evidence")
    }

    /// `partitions/<name>/sealing-keys/<key>/evidence/<report>.bin`.
    pub fn partition_sealing_key_evidence(&self, name: &str, key: &str, report: &str) -> PathBuf {
        self.partition_sealing_key_evidence_dir(name, key)
            .join(format!("{report}.bin"))
    }

    /// Resolve a parsed [`EvidenceRef`] to its evidence-bundle file path.
    pub fn evidence_ref_path(&self, reference: &EvidenceRef) -> PathBuf {
        self.partition_sealing_key_evidence(&reference.partition, &reference.key, &reference.report)
    }

    // --- Secure-domain subpaths ---------------------------------------------

    /// `secure-domains/<name>/secure-domain.json`.
    pub fn secure_domain_manifest(&self, name: &str) -> PathBuf {
        self.secure_domain_dir(name).join("secure-domain.json")
    }

    /// `secure-domains/<name>/policy.bin` — the domain's byte-identical policy.
    pub fn secure_domain_policy(&self, name: &str) -> PathBuf {
        self.secure_domain_dir(name).join("policy.bin")
    }

    /// `secure-domains/<name>/members/`.
    pub fn secure_domain_members_dir(&self, name: &str) -> PathBuf {
        self.secure_domain_dir(name).join("members")
    }

    /// `secure-domains/<name>/members/<partition>/`.
    pub fn secure_domain_member_dir(&self, name: &str, partition: &str) -> PathBuf {
        self.secure_domain_members_dir(name).join(partition)
    }

    /// `secure-domains/<name>/members/<partition>/member.json`.
    pub fn secure_domain_member_manifest(&self, name: &str, partition: &str) -> PathBuf {
        self.secure_domain_member_dir(name, partition)
            .join("member.json")
    }

    /// `secure-domains/<name>/members/<partition>/pok-local-backup.bin`.
    pub fn secure_domain_member_pok_local(&self, name: &str, partition: &str) -> PathBuf {
        self.secure_domain_member_dir(name, partition)
            .join("pok-local-backup.bin")
    }

    /// `secure-domains/<name>/members/<partition>/sd-mk-backup.bin`.
    pub fn secure_domain_member_sd_mk(&self, name: &str, partition: &str) -> PathBuf {
        self.secure_domain_member_dir(name, partition)
            .join("sd-mk-backup.bin")
    }

    /// `secure-domains/<name>/remote-backups/`.
    pub fn secure_domain_remote_backups_dir(&self, name: &str) -> PathBuf {
        self.secure_domain_dir(name).join("remote-backups")
    }

    /// `secure-domains/<name>/remote-backups/<destination>.bin`.
    pub fn secure_domain_remote_backup(&self, name: &str, destination: &str) -> PathBuf {
        self.secure_domain_remote_backups_dir(name)
            .join(format!("{destination}.bin"))
    }

    /// `secure-domains/<name>/peer-backups/`.
    pub fn secure_domain_peer_backups_dir(&self, name: &str) -> PathBuf {
        self.secure_domain_dir(name).join("peer-backups")
    }

    /// `secure-domains/<name>/peer-backups/<destination>.bin`.
    pub fn secure_domain_peer_backup(&self, name: &str, destination: &str) -> PathBuf {
        self.secure_domain_peer_backups_dir(name)
            .join(format!("{destination}.bin"))
    }

    /// Convert an absolute path under this workspace root into the POSIX,
    /// workspace-relative form manifests record.
    pub fn relative(&self, abs: &Path) -> Result<String, RelativeError> {
        let rel = abs.strip_prefix(&self.root).map_err(|_| RelativeError)?;
        let mut parts = Vec::new();
        for component in rel.components() {
            match component {
                std::path::Component::Normal(part) => {
                    parts.push(part.to_string_lossy().into_owned());
                }
                _ => return Err(RelativeError),
            }
        }
        Ok(parts.join("/"))
    }
}

/// The path is not a normal descendant of the workspace root.
#[derive(Debug, thiserror::Error)]
#[error("path is not under the workspace root")]
pub struct RelativeError;

/// A parsed `<partition>/<key>/<report>` evidence reference.
///
/// Evidence arguments are workspace references, not filesystem paths; they
/// resolve to `partitions/<partition>/sealing-keys/<key>/evidence/<report>.bin`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRef {
    /// Partition that owns the evidence bundle.
    pub partition: String,
    /// Sealing key the evidence attests.
    pub key: String,
    /// Evidence bundle (report) name.
    pub report: String,
}

impl EvidenceRef {
    /// Parse a `<partition>/<key>/<report>` reference. Each component must be a
    /// single non-empty path segment.
    pub fn parse(reference: &str) -> Result<Self, EvidenceRefError> {
        let parts: Vec<&str> = reference.split('/').collect();
        let [partition, key, report] = parts.as_slice() else {
            return Err(EvidenceRefError::Shape);
        };
        for component in [partition, key, report] {
            if component.is_empty() || component.contains('\\') {
                return Err(EvidenceRefError::Segment);
            }
        }
        Ok(Self {
            partition: (*partition).to_owned(),
            key: (*key).to_owned(),
            report: (*report).to_owned(),
        })
    }
}

/// Failure parsing an [`EvidenceRef`].
#[derive(Debug, thiserror::Error)]
pub enum EvidenceRefError {
    /// The reference did not have exactly three `/`-separated components.
    #[error("evidence reference must be <partition>/<key>/<report>")]
    Shape,
    /// A component was empty or contained an invalid character.
    #[error("evidence reference components must be non-empty path segments")]
    Segment,
}
