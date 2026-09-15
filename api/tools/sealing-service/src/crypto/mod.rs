// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side cryptographic machinery for the sealing-service CLI:
//! test-certificate assembly ([`certs`]), partition-policy handling
//! ([`policy`]), and DER key (de)serialization for authority-set persistence.

pub mod certs;
pub mod policy;

use azihsm_crypto::DerEccPrivateKey;
use azihsm_crypto::DerEccPublicKey;
use azihsm_crypto::EccCurve;

use crate::crypto::certs::CaKey;
use crate::crypto::certs::RAW_PUB_LEN;
use crate::crypto::certs::SCALAR_LEN;
use crate::error::Error;
use crate::error::Result;

/// Encode a CA key's private scalar (with public coordinates) as an RFC 5915
/// SEC1 EC private key in DER, for persistence under an authority set's
/// `secrets/` directory.
pub fn ca_private_key_der(ca: &CaKey) -> Result<Vec<u8>> {
    let scalar = ca.scalar()?;
    let raw = ca.raw_pub();
    let (x, y) = raw.split_at(SCALAR_LEN);
    let der =
        DerEccPrivateKey::new_with_pub_key(EccCurve::P384, &scalar, x, y).map_err(Error::crypto)?;
    der.to_der_vec().map_err(Error::crypto)
}

/// Reload a CA key from an RFC 5915 SEC1 EC private key in DER.
pub fn ca_from_private_key_der(bytes: &[u8]) -> Result<CaKey> {
    let der = DerEccPrivateKey::from_der(bytes).map_err(Error::crypto)?;
    CaKey::from_scalar(der.priv_key())
}

/// Encode a raw `X ‖ Y` P-384 public key as an X.509 `SubjectPublicKeyInfo`
/// in DER.
pub fn public_key_der(raw_pub: &[u8; RAW_PUB_LEN]) -> Result<Vec<u8>> {
    let (x, y) = raw_pub.split_at(SCALAR_LEN);
    let der = DerEccPublicKey::new(EccCurve::P384, x, y).map_err(Error::crypto)?;
    let len = der.to_der(None).map_err(Error::crypto)?;
    let mut out = vec![0u8; len];
    let written = der.to_der(Some(&mut out)).map_err(Error::crypto)?;
    out.truncate(written);
    Ok(out)
}
