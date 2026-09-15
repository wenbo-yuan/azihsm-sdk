// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side X.509 test-certificate machinery.
//!
//! This is a CLI-owned port of the certificate helpers in
//! `api/tests/src/utils/sd_provision.rs`. It builds the self-signed roots,
//! POTA-anchored PTA chains, and root-to-leaf PID attestation chains that
//! `part_final_ex` and the sealing-service evidence flows require. The
//! underlying builders in [`azihsm_crypto::x509_builder`] are public; only the
//! test fixture's glue is reproduced here.
//!
//! The deep certificate-assembly helpers operate on fixed-size templates and
//! validated P-384 keys, so their internal buffer and encoding steps are
//! infallible by construction and use `expect`; the public entry points that
//! generate or reload key material return [`Result`].

use azihsm_crypto::EccCurve;
use azihsm_crypto::EccKeyOp;
use azihsm_crypto::EccPrivateKey;
use azihsm_crypto::EcdsaAlgo;
use azihsm_crypto::ExportableHsmKey;
use azihsm_crypto::HashAlgo;
use azihsm_crypto::HashOp;
use azihsm_crypto::SignOp;
use azihsm_crypto::x509_builder::cert_builder;
use azihsm_crypto::x509_builder::cert_builder::CN_LEN;
use azihsm_crypto::x509_builder::cert_builder::IntermediateCertParams;
use azihsm_crypto::x509_builder::cert_builder::KeyUsage;
use azihsm_crypto::x509_builder::cert_builder::LeafCertParams;
use azihsm_crypto::x509_builder::cert_builder::RootCertParams;
use azihsm_crypto::x509_builder::cert_builder::SN_LEN;
use azihsm_crypto::x509_builder::cert_builder::pad_cn;
use azihsm_crypto::x509_builder::cert_builder::pad_sn;
use azihsm_crypto::x509_builder::intermediate_cert;
use azihsm_crypto::x509_builder::leaf_cert;
use azihsm_crypto::x509_builder::root_cert;

use crate::error::Error;
use crate::error::Result;

/// Length of a P-384 SEC1 uncompressed public key (`0x04 ‖ X ‖ Y`).
pub const SEC1_PUB_LEN: usize = 97;
/// Length of raw P-384 `X ‖ Y` public coordinates.
pub const RAW_PUB_LEN: usize = 96;
/// Length of the P-384 private scalar.
pub const SCALAR_LEN: usize = 48;

const NOT_BEFORE: &[u8; 15] = b"20250101000000Z";
const NOT_AFTER: &[u8; 15] = b"20350101000000Z";
const ROOT_CN: &str = "AZIHSM POTA Root CA";
const ROOT_SN: &str = "POTAROOT1";
const PTA_CN: &str = "AZIHSM PTA Intermediate CA";
const PTA_SN: &str = "PTAINT001";
const LEAF_CN: &str = "AZIHSM Evidence Leaf";
const LEAF_SN: &str = "EVLEAF001";

/// A synthetic P-384 CA key that signs certificates and exposes its public
/// key. Used for each of the four test authorities (manufacturer, owner,
/// SATA, POTA) and for any ad-hoc self-signed root.
pub struct CaKey {
    private_key: EccPrivateKey,
    pub_sec1: [u8; SEC1_PUB_LEN],
}

impl CaKey {
    /// Generate a fresh P-384 CA key.
    pub fn generate() -> Result<Self> {
        let private_key = EccPrivateKey::from_curve(EccCurve::P384).map_err(Error::crypto)?;
        Self::from_private_key(private_key)
    }

    /// Reload a CA key from its raw big-endian private scalar (48 bytes).
    pub fn from_scalar(scalar: &[u8]) -> Result<Self> {
        let private_key =
            EccPrivateKey::from_scalar(EccCurve::P384, scalar).map_err(Error::crypto)?;
        Self::from_private_key(private_key)
    }

    fn from_private_key(private_key: EccPrivateKey) -> Result<Self> {
        let (x, y) = private_key.coord_vec().map_err(Error::crypto)?;
        if x.len() != SCALAR_LEN || y.len() != SCALAR_LEN {
            return Err(Error::crypto("unexpected P-384 coordinate length"));
        }
        let mut pub_sec1 = [0u8; SEC1_PUB_LEN];
        pub_sec1[0] = 0x04;
        pub_sec1[1..49].copy_from_slice(&x);
        pub_sec1[49..97].copy_from_slice(&y);
        Ok(Self {
            private_key,
            pub_sec1,
        })
    }

    /// The raw big-endian private scalar (48 bytes), for persistence.
    pub fn scalar(&self) -> Result<Vec<u8>> {
        self.private_key.to_hsm_bytes_vec().map_err(Error::crypto)
    }

    /// Raw `X ‖ Y` (96-byte) public coordinates — the policy pubkey form.
    pub fn raw_pub(&self) -> [u8; RAW_PUB_LEN] {
        let mut raw = [0u8; RAW_PUB_LEN];
        raw.copy_from_slice(&self.pub_sec1[1..]);
        raw
    }

    /// The SEC1 uncompressed public key (`0x04 ‖ X ‖ Y`).
    pub fn pub_sec1(&self) -> &[u8; SEC1_PUB_LEN] {
        &self.pub_sec1
    }

    /// SHA-1 of the SEC1 public key — the Subject Key Identifier.
    fn ski(&self) -> [u8; 20] {
        sha1_ski(&self.pub_sec1)
    }

    /// ECDSA-P384 / SHA-384 sign `tbs`, returning `(r, s)` (48 bytes each).
    fn sign(&self, tbs: &[u8]) -> ([u8; 48], [u8; 48]) {
        let mut algo = EcdsaAlgo::new(HashAlgo::sha384());
        let mut sig = [0u8; 96];
        let written = algo
            .sign(&self.private_key, tbs, Some(&mut sig))
            .expect("P-384 ECDSA sign into a 96-byte buffer");
        assert_eq!(written, 96, "P-384 raw signature is 96 bytes");
        let mut r = [0u8; 48];
        let mut s = [0u8; 48];
        r.copy_from_slice(&sig[..48]);
        s.copy_from_slice(&sig[48..]);
        (r, s)
    }
}

/// A generated PTA chain (root -> PTA), DER-encoded, root-first.
pub struct PtaChain {
    /// The self-signed POTA root certificate.
    pub root_der: Vec<u8>,
    /// The PTA intermediate certificate signed by the POTA root.
    pub pta_der: Vec<u8>,
}

/// A generated root -> leaf attestation chain, DER-encoded.
pub struct GeneratedChain {
    /// The self-signed CA (root) certificate.
    pub root_der: Vec<u8>,
    /// The end-entity leaf certificate.
    pub leaf_der: Vec<u8>,
}

/// SHA-1 of a SEC1 public key (Subject / Authority Key Identifier).
fn sha1_ski(sec1: &[u8; SEC1_PUB_LEN]) -> [u8; 20] {
    let mut algo = HashAlgo::sha1();
    let mut out = [0u8; 20];
    algo.hash(sec1, Some(&mut out)).expect("sha1 of SEC1 key");
    out
}

/// A 20-byte positive DER serial number seeded from `tag`.
fn serial(tag: u8) -> [u8; 20] {
    let mut s = [0u8; 20];
    s[0] = tag & 0x7F;
    for (i, b) in s.iter_mut().enumerate().skip(1) {
        *b = tag.wrapping_add(i as u8);
    }
    s
}

/// Build a self-signed POTA root CA certificate (DER).
fn build_root(ca: &CaKey) -> Vec<u8> {
    let params = RootCertParams {
        public_key: &ca.pub_sec1,
        serial_number: &serial(1),
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
        subject_cn: ROOT_CN,
        subject_sn: ROOT_SN,
        subject_key_id: &ca.ski(),
    };
    let mut tbs = root_cert::TBS_TEMPLATE;
    patch_tbs_root(&mut tbs, &params);
    let (r, s) = ca.sign(&tbs);
    let mut out = vec![0u8; 1024];
    let len = cert_builder::build_root_cert(&params, &r, &s, &mut out).expect("build root cert");
    out.truncate(len);
    out
}

/// Build the PTA intermediate CA certificate carrying the partition PTA key,
/// signed by `issuer` (the POTA CA).
fn build_pta_intermediate(pta_pub_sec1: &[u8; SEC1_PUB_LEN], issuer: &CaKey) -> Vec<u8> {
    let params = IntermediateCertParams {
        public_key: pta_pub_sec1,
        serial_number: &serial(2),
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
        subject_cn: PTA_CN,
        subject_sn: PTA_SN,
        issuer_cn: ROOT_CN,
        issuer_sn: ROOT_SN,
        subject_key_id: &sha1_ski(pta_pub_sec1),
        authority_key_id: &issuer.ski(),
        path_len: 0,
    };
    let mut tbs = intermediate_cert::TBS_TEMPLATE;
    patch_tbs_intermediate(&mut tbs, &params);
    let (r, s) = issuer.sign(&tbs);
    let mut out = vec![0u8; 1024];
    let len = cert_builder::build_intermediate_cert(&params, &r, &s, &mut out)
        .expect("build PTA intermediate cert");
    out.truncate(len);
    out
}

/// Build an end-entity leaf certificate whose subject public key is
/// `leaf_pub_sec1`, signed by `issuer`.
fn build_leaf(leaf_pub_sec1: &[u8; SEC1_PUB_LEN], issuer: &CaKey) -> Vec<u8> {
    let params = LeafCertParams {
        public_key: leaf_pub_sec1,
        serial_number: &serial(3),
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
        subject_cn: LEAF_CN,
        subject_sn: LEAF_SN,
        issuer_cn: ROOT_CN,
        issuer_sn: ROOT_SN,
        subject_key_id: &sha1_ski(leaf_pub_sec1),
        authority_key_id: &issuer.ski(),
        key_usage: KeyUsage::DIGITAL_SIGNATURE,
    };
    let mut tbs = leaf_cert::TBS_TEMPLATE;
    patch_tbs_leaf(&mut tbs, &params);
    let (r, s) = issuer.sign(&tbs);
    let mut out = vec![0u8; 1024];
    let len = cert_builder::build_leaf_cert(&params, &r, &s, &mut out).expect("build leaf cert");
    out.truncate(len);
    out
}

/// Build a self-signed root CA certificate (DER) for `ca`.
pub fn root_certificate(ca: &CaKey) -> Vec<u8> {
    build_root(ca)
}

/// Build a POTA-anchored root -> PTA chain from the partition PTA key.
pub fn make_pta_chain(pota_ca: &CaKey, pta_pub_sec1: &[u8; SEC1_PUB_LEN]) -> PtaChain {
    PtaChain {
        root_der: build_root(pota_ca),
        pta_der: build_pta_intermediate(pta_pub_sec1, pota_ca),
    }
}

/// Build a root -> leaf chain: a self-signed root CA (`ca`) certifying an
/// end-entity leaf that carries `leaf_pub_raw` (raw `X ‖ Y`).
pub fn make_chain(ca: &CaKey, leaf_pub_raw: &[u8; RAW_PUB_LEN]) -> GeneratedChain {
    let mut leaf_sec1 = [0u8; SEC1_PUB_LEN];
    leaf_sec1[0] = 0x04;
    leaf_sec1[1..].copy_from_slice(leaf_pub_raw);
    GeneratedChain {
        root_der: build_root(ca),
        leaf_der: build_leaf(&leaf_sec1, ca),
    }
}

/// Extract the SEC1 uncompressed public key (`0x04 ‖ X ‖ Y`) from a DER
/// PKCS#10 CSR.
pub fn pta_pub_from_csr(csr: &[u8]) -> Result<[u8; SEC1_PUB_LEN]> {
    let (_, cr, _) = der_tlv(csr)?; // CertificationRequest
    let (_, cri, _) = der_tlv(cr)?; // certificationRequestInfo
    let (_, _version, after_version) = der_tlv(cri)?;
    let (_, _subject, after_subject) = der_tlv(after_version)?;
    let (_, spki, _) = der_tlv(after_subject)?;
    let (_, _algorithm, after_algorithm) = der_tlv(spki)?;
    let (tag, bit_string, _) = der_tlv(after_algorithm)?;
    if tag != 0x03 {
        return Err(Error::crypto("CSR subjectPublicKey must be a BIT STRING"));
    }
    let point = bit_string
        .get(1..)
        .ok_or_else(|| Error::crypto("CSR BIT STRING missing unused-bits octet"))?;
    if point.len() != SEC1_PUB_LEN || point[0] != 0x04 {
        return Err(Error::crypto(
            "CSR public key is not a P-384 uncompressed point",
        ));
    }
    let mut out = [0u8; SEC1_PUB_LEN];
    out.copy_from_slice(point);
    Ok(out)
}

/// Extract the SEC1 uncompressed public key (`0x04 ‖ X ‖ Y`) from a DER
/// X.509 `SubjectPublicKeyInfo` (as written by
/// [`crate::crypto::public_key_der`]).
pub fn pub_sec1_from_spki(der: &[u8]) -> Result<[u8; SEC1_PUB_LEN]> {
    let (_, spki, _) = der_tlv(der)?; // SubjectPublicKeyInfo
    let (_, _algorithm, after_algorithm) = der_tlv(spki)?;
    let (tag, bit_string, _) = der_tlv(after_algorithm)?;
    if tag != 0x03 {
        return Err(Error::crypto("SPKI subjectPublicKey must be a BIT STRING"));
    }
    let point = bit_string
        .get(1..)
        .ok_or_else(|| Error::crypto("SPKI BIT STRING missing unused-bits octet"))?;
    if point.len() != SEC1_PUB_LEN || point[0] != 0x04 {
        return Err(Error::crypto(
            "SPKI public key is not a P-384 uncompressed point",
        ));
    }
    let mut out = [0u8; SEC1_PUB_LEN];
    out.copy_from_slice(point);
    Ok(out)
}

/// Read one DER TLV: returns `(tag, contents, rest)`.
fn der_tlv(der: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    if der.len() < 2 {
        return Err(Error::crypto("DER TLV: missing tag/length octet"));
    }
    let tag = der[0];
    let len_octet = der[1];
    let (len, header) = if len_octet & 0x80 == 0 {
        (usize::from(len_octet), 2)
    } else {
        let n = usize::from(len_octet & 0x7F);
        if der.len() < 2 + n {
            return Err(Error::crypto("DER TLV: truncated long-form length"));
        }
        let mut len = 0usize;
        for &b in &der[2..2 + n] {
            len = (len << 8) | usize::from(b);
        }
        (len, 2 + n)
    };
    if der.len() < header + len {
        return Err(Error::crypto("DER TLV: truncated content"));
    }
    Ok((tag, &der[header..header + len], &der[header + len..]))
}

/// Patch a root-cert TBS template with the variable field values.
fn patch_tbs_root(tbs: &mut [u8], params: &RootCertParams<'_>) {
    let cn = pad_cn(params.subject_cn).expect("subject CN fits the CN field");
    let sn = pad_sn(params.subject_sn).expect("subject SN fits the SN field");
    tbs[root_cert::PUBLIC_KEY_OFFSET..root_cert::PUBLIC_KEY_OFFSET + 97]
        .copy_from_slice(params.public_key);
    tbs[root_cert::SERIAL_NUMBER_OFFSET..root_cert::SERIAL_NUMBER_OFFSET + 20]
        .copy_from_slice(params.serial_number);
    tbs[root_cert::NOT_BEFORE_OFFSET..root_cert::NOT_BEFORE_OFFSET + 15]
        .copy_from_slice(params.not_before);
    tbs[root_cert::NOT_AFTER_OFFSET..root_cert::NOT_AFTER_OFFSET + 15]
        .copy_from_slice(params.not_after);
    tbs[root_cert::ISSUER_CN_OFFSET..root_cert::ISSUER_CN_OFFSET + CN_LEN].copy_from_slice(&cn);
    tbs[root_cert::SUBJECT_CN_OFFSET..root_cert::SUBJECT_CN_OFFSET + CN_LEN].copy_from_slice(&cn);
    tbs[root_cert::ISSUER_SN_OFFSET..root_cert::ISSUER_SN_OFFSET + SN_LEN].copy_from_slice(&sn);
    tbs[root_cert::SUBJECT_SN_OFFSET..root_cert::SUBJECT_SN_OFFSET + SN_LEN].copy_from_slice(&sn);
    tbs[root_cert::SUBJECT_KEY_ID_OFFSET..root_cert::SUBJECT_KEY_ID_OFFSET + 20]
        .copy_from_slice(params.subject_key_id);
}

/// Patch an intermediate-cert TBS template with the variable field values.
fn patch_tbs_intermediate(tbs: &mut [u8], params: &IntermediateCertParams<'_>) {
    let s_cn = pad_cn(params.subject_cn).expect("subject CN fits the CN field");
    let i_cn = pad_cn(params.issuer_cn).expect("issuer CN fits the CN field");
    let s_sn = pad_sn(params.subject_sn).expect("subject SN fits the SN field");
    let i_sn = pad_sn(params.issuer_sn).expect("issuer SN fits the SN field");
    tbs[intermediate_cert::PUBLIC_KEY_OFFSET..intermediate_cert::PUBLIC_KEY_OFFSET + 97]
        .copy_from_slice(params.public_key);
    tbs[intermediate_cert::SERIAL_NUMBER_OFFSET..intermediate_cert::SERIAL_NUMBER_OFFSET + 20]
        .copy_from_slice(params.serial_number);
    tbs[intermediate_cert::NOT_BEFORE_OFFSET..intermediate_cert::NOT_BEFORE_OFFSET + 15]
        .copy_from_slice(params.not_before);
    tbs[intermediate_cert::NOT_AFTER_OFFSET..intermediate_cert::NOT_AFTER_OFFSET + 15]
        .copy_from_slice(params.not_after);
    tbs[intermediate_cert::ISSUER_CN_OFFSET..intermediate_cert::ISSUER_CN_OFFSET + CN_LEN]
        .copy_from_slice(&i_cn);
    tbs[intermediate_cert::SUBJECT_CN_OFFSET..intermediate_cert::SUBJECT_CN_OFFSET + CN_LEN]
        .copy_from_slice(&s_cn);
    tbs[intermediate_cert::ISSUER_SN_OFFSET..intermediate_cert::ISSUER_SN_OFFSET + SN_LEN]
        .copy_from_slice(&i_sn);
    tbs[intermediate_cert::SUBJECT_SN_OFFSET..intermediate_cert::SUBJECT_SN_OFFSET + SN_LEN]
        .copy_from_slice(&s_sn);
    tbs[intermediate_cert::SUBJECT_KEY_ID_OFFSET..intermediate_cert::SUBJECT_KEY_ID_OFFSET + 20]
        .copy_from_slice(params.subject_key_id);
    tbs[intermediate_cert::AUTHORITY_KEY_ID_OFFSET
        ..intermediate_cert::AUTHORITY_KEY_ID_OFFSET + 20]
        .copy_from_slice(params.authority_key_id);
    tbs[intermediate_cert::PATH_LEN_OFFSET] = params.path_len;
}

/// Patch a leaf-cert TBS template with the variable field values.
fn patch_tbs_leaf(tbs: &mut [u8], params: &LeafCertParams<'_>) {
    let s_cn = pad_cn(params.subject_cn).expect("subject CN fits the CN field");
    let i_cn = pad_cn(params.issuer_cn).expect("issuer CN fits the CN field");
    let s_sn = pad_sn(params.subject_sn).expect("subject SN fits the SN field");
    let i_sn = pad_sn(params.issuer_sn).expect("issuer SN fits the SN field");
    tbs[leaf_cert::PUBLIC_KEY_OFFSET..leaf_cert::PUBLIC_KEY_OFFSET + 97]
        .copy_from_slice(params.public_key);
    tbs[leaf_cert::SERIAL_NUMBER_OFFSET..leaf_cert::SERIAL_NUMBER_OFFSET + 20]
        .copy_from_slice(params.serial_number);
    tbs[leaf_cert::NOT_BEFORE_OFFSET..leaf_cert::NOT_BEFORE_OFFSET + 15]
        .copy_from_slice(params.not_before);
    tbs[leaf_cert::NOT_AFTER_OFFSET..leaf_cert::NOT_AFTER_OFFSET + 15]
        .copy_from_slice(params.not_after);
    tbs[leaf_cert::ISSUER_CN_OFFSET..leaf_cert::ISSUER_CN_OFFSET + CN_LEN].copy_from_slice(&i_cn);
    tbs[leaf_cert::SUBJECT_CN_OFFSET..leaf_cert::SUBJECT_CN_OFFSET + CN_LEN].copy_from_slice(&s_cn);
    tbs[leaf_cert::ISSUER_SN_OFFSET..leaf_cert::ISSUER_SN_OFFSET + SN_LEN].copy_from_slice(&i_sn);
    tbs[leaf_cert::SUBJECT_SN_OFFSET..leaf_cert::SUBJECT_SN_OFFSET + SN_LEN].copy_from_slice(&s_sn);
    tbs[leaf_cert::SUBJECT_KEY_ID_OFFSET..leaf_cert::SUBJECT_KEY_ID_OFFSET + 20]
        .copy_from_slice(params.subject_key_id);
    tbs[leaf_cert::AUTHORITY_KEY_ID_OFFSET..leaf_cert::AUTHORITY_KEY_ID_OFFSET + 20]
        .copy_from_slice(params.authority_key_id);
    tbs[leaf_cert::KEY_USAGE_OFFSET..leaf_cert::KEY_USAGE_OFFSET + 2]
        .copy_from_slice(&params.key_usage.to_bytes());
}
