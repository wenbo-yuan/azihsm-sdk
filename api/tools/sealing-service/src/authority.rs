// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Reusable test authority sets.
//!
//! An authority set is the four test CA keys (manufacturer, owner, SATA, POTA)
//! that endorse a partition's identity and issue its evidence chains, plus the
//! single backing-partition policy derived from the SATA and POTA anchors. The
//! keys are persisted so additional partitions can reuse the exact same policy
//! and SATA anchor, which cross-partition remote restore and reseal require.
//!
//! See the "Authority and certificate implementation gap analysis" and
//! `authority-set.json` sections of `api/docs/design-sealing-service-cli.md`.

use std::path::Path;

use crate::crypto;
use crate::crypto::certs::CaKey;
use crate::error::Error;
use crate::error::Result;
use crate::manifest::Authorities;
use crate::manifest::Authority;
use crate::manifest::AuthoritySetManifest;
use crate::manifest::CertificateRules;
use crate::manifest::FileRef;
use crate::manifest::SCHEMA_VERSION;
use crate::manifest::Validity;
use crate::util;
use crate::workspace::Workspace;

/// Default certificate subject template.
const SUBJECT_TEMPLATE: &str = "CN={role} {authority_set},O=AZIHSM Sealing Service,OU=Authority";

/// Default certificate validity in days (ten years).
const DURATION_DAYS: u32 = 3650;

/// The four test CA authorities of one named authority set.
pub struct AuthoritySet {
    /// The authority-set name.
    pub name: String,
    /// Manufacturer authority (issues the manufacturer PID chain).
    pub manufacturer: CaKey,
    /// Owner authority (issues the owner PID chain).
    pub owner: CaKey,
    /// SATA authority (issues the partition-owner PID chain; anchors policy).
    pub sata: CaKey,
    /// POTA authority (endorses partition identity; anchors policy and PTA).
    pub pota: CaKey,
}

impl AuthoritySet {
    /// Generate a fresh authority set with four new P-384 CA keys.
    pub fn generate(name: &str) -> Result<Self> {
        Ok(Self {
            name: name.to_owned(),
            manufacturer: CaKey::generate()?,
            owner: CaKey::generate()?,
            sata: CaKey::generate()?,
            pota: CaKey::generate()?,
        })
    }

    /// Load an existing authority set's four CA keys from its `secrets/`
    /// directory.
    pub fn load(ws: &Workspace, name: &str) -> Result<Self> {
        let dir = ws.authority_set_secrets_dir(name);
        Ok(Self {
            name: name.to_owned(),
            manufacturer: load_key(&dir.join("manufacturer-private-key.der"))?,
            owner: load_key(&dir.join("owner-private-key.der"))?,
            sata: load_key(&dir.join("sata-private-key.der"))?,
            pota: load_key(&dir.join("pota-private-key.der"))?,
        })
    }

    /// Persist the four authorities (public roots and private keys), the
    /// backing `policy.bin`, and `authority-set.json`. Returns the policy
    /// reference recorded by dependent manifests.
    pub fn persist(
        &self,
        ws: &Workspace,
        created_utc: &str,
        policy_bytes: &[u8],
    ) -> Result<FileRef> {
        let roots_dir = ws.authority_set_roots_dir(&self.name);
        let secrets_dir = ws.authority_set_secrets_dir(&self.name);
        util::create_dir_all(&roots_dir)?;
        util::create_dir_all(&secrets_dir)?;

        let manufacturer = self.persist_authority(ws, "manufacturer", &self.manufacturer)?;
        let owner = self.persist_authority(ws, "owner", &self.owner)?;
        let sata = self.persist_authority(ws, "sata", &self.sata)?;
        let pota = self.persist_authority(ws, "pota", &self.pota)?;

        let policy = self.persist_policy(ws, policy_bytes)?;

        let manifest = AuthoritySetManifest {
            schema_version: SCHEMA_VERSION,
            kind: "authority-set".to_owned(),
            name: self.name.clone(),
            created_utc: created_utc.to_owned(),
            algorithm: "ecdsa".to_owned(),
            curve: "p384".to_owned(),
            authorities: Authorities {
                manufacturer,
                owner,
                sata,
                pota,
                sapota: None,
            },
            certificate_rules: CertificateRules {
                subject_template: SUBJECT_TEMPLATE.to_owned(),
                serial_method: "random-128-bit".to_owned(),
                validity: Validity {
                    not_before: created_utc.to_owned(),
                    duration_days: DURATION_DAYS,
                },
            },
            backing_policy: policy.clone(),
        };
        crate::manifest::write(&ws.authority_set_manifest(&self.name), &manifest)?;

        Ok(policy)
    }

    fn persist_authority(&self, ws: &Workspace, role: &str, ca: &CaKey) -> Result<Authority> {
        let root_der = crypto::certs::root_certificate(ca);
        let key_der = crypto::ca_private_key_der(ca)?;

        let root_path = ws
            .authority_set_roots_dir(&self.name)
            .join(format!("{role}-root.der"));
        let key_path = ws
            .authority_set_secrets_dir(&self.name)
            .join(format!("{role}-private-key.der"));

        util::write_atomic(&root_path, &root_der)?;
        util::write_secret(&key_path, &key_der)?;

        Ok(Authority {
            root_cert: rel(ws, &root_path)?,
            private_key: rel(ws, &key_path)?,
            public_key_sha384: util::sha384_hex(&ca.raw_pub()),
            root_cert_sha384: util::sha384_hex(&root_der),
        })
    }

    fn persist_policy(&self, ws: &Workspace, policy_bytes: &[u8]) -> Result<FileRef> {
        let path = ws.authority_set_policy(&self.name);
        util::write_atomic(&path, policy_bytes)?;
        Ok(FileRef {
            path: rel(ws, &path)?,
            sha384: util::sha384_hex(policy_bytes),
        })
    }
}

/// Compute the on-disk backing-policy reference for an existing authority set.
pub fn policy_file_ref(ws: &Workspace, name: &str) -> Result<FileRef> {
    let path = ws.authority_set_policy(name);
    let (sha384, _len) = util::file_digest(&path)?;
    Ok(FileRef {
        path: rel(ws, &path)?,
        sha384,
    })
}

fn load_key(path: &Path) -> Result<CaKey> {
    if !path.exists() {
        return Err(Error::NotFound {
            what: "authority private key",
            path: path.to_path_buf(),
        });
    }
    let der = util::read_file(path)?;
    crypto::ca_from_private_key_der(&der)
}

fn rel(ws: &Workspace, abs: &Path) -> Result<String> {
    ws.relative(abs)
        .map_err(|err| Error::Internal(err.to_string()))
}
