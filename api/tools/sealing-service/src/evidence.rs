// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Persisted secure-domain evidence bundle.
//!
//! [`HsmSdEvidence`](azihsm_api::HsmSdEvidence) is a borrowed SDK structure —
//! three arrays of DER certificate slices and one COSE_Sign1 report slice — for
//! which the SDK defines no persisted serialization (see the "evidence bundle"
//! discussion in `api/docs/design-sealing-service-cli.md`). This module defines
//! the CLI's own on-disk container so evidence `key_report` generates for one
//! partition can be supplied to a secure-domain operation on another.
//!
//! The bundle holds only public attestation material — three certificate chains
//! (each an ordered root → leaf DER list) and the COSE_Sign1 key report. It
//! never contains a sealing private key or any masking key.
//!
//! # Container format
//!
//! A little-endian, length-prefixed binary layout (version 1):
//!
//! ```text
//! magic    : 8 bytes  = b"AZSDEV01"   (format tag + version)
//! for each of [manufacturer, owner, partition-owner] chain, in order:
//!   count  : u16      number of certificates in the chain
//!   for each certificate:
//!     len  : u32      certificate DER length
//!     der  : len bytes
//! report_len : u32    COSE_Sign1 report length
//! report     : report_len bytes
//! ```

use azihsm_api::HsmCert;
use azihsm_api::HsmSdEvidence;

use crate::error::Error;
use crate::error::Result;

const MAGIC: [u8; 8] = *b"AZSDEV01";

/// An owned secure-domain evidence bundle: three DER certificate chains (each
/// an ordered root → leaf list) and the COSE_Sign1 key report.
pub struct EvidenceBundle {
    manufacturer_chain: Vec<Vec<u8>>,
    owner_chain: Vec<Vec<u8>>,
    partition_owner_chain: Vec<Vec<u8>>,
    report: Vec<u8>,
}

impl EvidenceBundle {
    /// Assemble a bundle from its three chains and the key report.
    pub fn new(
        manufacturer_chain: Vec<Vec<u8>>,
        owner_chain: Vec<Vec<u8>>,
        partition_owner_chain: Vec<Vec<u8>>,
        report: Vec<u8>,
    ) -> Self {
        Self {
            manufacturer_chain,
            owner_chain,
            partition_owner_chain,
            report,
        }
    }

    /// The embedded COSE_Sign1 key report.
    pub fn report(&self) -> &[u8] {
        &self.report
    }

    /// Return `true` if every certificate chain's leaf embeds `sec1` — the
    /// 97-byte SEC1 point of the report-signing PID public key. This is the
    /// host-side fast-fail that the three chains agree on one attested
    /// identity; the firmware performs the authoritative signature, SATA-anchor
    /// and policy-binding checks when the bundle is consumed.
    pub fn chains_bind_pid(&self, sec1: &[u8]) -> bool {
        [
            &self.manufacturer_chain,
            &self.owner_chain,
            &self.partition_owner_chain,
        ]
        .iter()
        .all(|chain| {
            chain
                .last()
                .is_some_and(|leaf| leaf.windows(sec1.len()).any(|w| w == sec1))
        })
    }

    /// Serialize the bundle into its length-prefixed container.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        for chain in [
            &self.manufacturer_chain,
            &self.owner_chain,
            &self.partition_owner_chain,
        ] {
            out.extend_from_slice(&(chain.len() as u16).to_le_bytes());
            for cert in chain {
                out.extend_from_slice(&(cert.len() as u32).to_le_bytes());
                out.extend_from_slice(cert);
            }
        }
        out.extend_from_slice(&(self.report.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.report);
        out
    }

    /// Parse a bundle from its container bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let magic = r.take(MAGIC.len())?;
        if magic != MAGIC {
            return Err(malformed("bad magic"));
        }
        let manufacturer_chain = r.chain()?;
        let owner_chain = r.chain()?;
        let partition_owner_chain = r.chain()?;
        let report_len = r.u32()? as usize;
        let report = r.take(report_len)?.to_vec();
        if !r.is_empty() {
            return Err(malformed("trailing bytes"));
        }
        Ok(Self {
            manufacturer_chain,
            owner_chain,
            partition_owner_chain,
            report,
        })
    }

    /// Build a borrowed [`HsmSdEvidence`] over the owned chains and report and
    /// pass it to `f`. The `HsmCert` arrays live only for the duration of the
    /// call, so the evidence is delivered through a closure.
    pub fn with_hsm_evidence<R>(&self, f: impl FnOnce(&HsmSdEvidence<'_>) -> R) -> R {
        let mfgr = to_certs(&self.manufacturer_chain);
        let owner = to_certs(&self.owner_chain);
        let part_owner = to_certs(&self.partition_owner_chain);
        f(&HsmSdEvidence {
            mfgr_cert_chain: &mfgr,
            owner_cert_chain: &owner,
            part_owner_cert_chain: &part_owner,
            report: &self.report,
        })
    }
}

/// Borrow a chain of owned DER buffers as `HsmCert` descriptors.
fn to_certs(chain: &[Vec<u8>]) -> Vec<HsmCert<'_>> {
    chain.iter().map(|c| HsmCert { cert: c }).collect()
}

/// Build a malformed-bundle error.
fn malformed(detail: impl std::fmt::Display) -> Error {
    Error::Evidence(format!("malformed evidence bundle: {detail}"))
}

/// A bounds-checked forward reader over the container bytes.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos == self.bytes.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| malformed("length overflow"))?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| malformed("unexpected end of input"))?;
        self.pos = end;
        Ok(slice)
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn chain(&mut self) -> Result<Vec<Vec<u8>>> {
        let count = self.u16()? as usize;
        let mut chain = Vec::with_capacity(count);
        for _ in 0..count {
            let len = self.u32()? as usize;
            chain.push(self.take(len)?.to_vec());
        }
        Ok(chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let bundle = EvidenceBundle::new(
            vec![vec![1, 2, 3], vec![4, 5]],
            vec![vec![6], vec![7, 8, 9, 10]],
            vec![vec![11, 12], vec![13]],
            vec![0xAA; 200],
        );
        let encoded = bundle.encode();
        let decoded = EvidenceBundle::decode(&encoded).expect("decode");
        assert_eq!(decoded.manufacturer_chain, bundle.manufacturer_chain);
        assert_eq!(decoded.owner_chain, bundle.owner_chain);
        assert_eq!(decoded.partition_owner_chain, bundle.partition_owner_chain);
        assert_eq!(decoded.report, bundle.report);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut encoded = EvidenceBundle::new(vec![], vec![], vec![], vec![]).encode();
        encoded[0] ^= 0xFF;
        assert!(EvidenceBundle::decode(&encoded).is_err());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut encoded = EvidenceBundle::new(vec![], vec![], vec![], vec![1]).encode();
        encoded.push(0);
        assert!(EvidenceBundle::decode(&encoded).is_err());
    }

    #[test]
    fn rejects_truncated() {
        let encoded = EvidenceBundle::new(vec![vec![1, 2, 3]], vec![], vec![], vec![]).encode();
        assert!(EvidenceBundle::decode(&encoded[..encoded.len() - 2]).is_err());
    }
}
