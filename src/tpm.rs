// Copyright (C) 2024, 2026 Krishap <krishapbusiness@gmail.com>
//
// This file is part of gkey.
//
// gkey is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// gkey is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
// License for more details.
//
// You should have received a copy of the GNU General Public License
// along with gkey.  If not, see <https://www.gnu.org/licenses/>.

//! The TPM root of trust.
//!
//! All key material handled by gkey is rooted in a storage primary
//! key that the TPM derives deterministically from the seed of its
//! owner (storage) hierarchy.  Nothing is written to the TPM's
//! non-volatile memory: the primary key is re-derived each time a
//! connection is opened, and the objects created under it are stored
//! on disk as blobs that only this particular TPM can load.
//!
//! Commands are sent inside an HMAC session salted with the primary
//! key, so that secrets crossing the bus between the CPU and the TPM
//! (the sealed keystore key in particular) are encrypted.

use std::str::FromStr;

use sha2::{Digest as _, Sha256};
use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK};
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{KeyHandle, ObjectHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{
    Digest, EccPoint, EccScheme, HashScheme, HashcheckTicket, KeyedHashScheme, Private, Public,
    PublicBuilder, PublicEccParametersBuilder, PublicKeyedHashParameters, SensitiveData, Signature,
    SignatureScheme, SymmetricDefinition, SymmetricDefinitionObject,
};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;
use tss_esapi::utils::PublicKey;
use tss_esapi::{Context, TctiNameConf};
use zeroize::Zeroizing;

use crate::prelude::*;

/// TCTI used when none is given on the command line or in the
/// environment.  The kernel resource manager allows several programs
/// to share the TPM.
pub const DEFAULT_TCTI: &str = "device:/dev/tpmrm0";

/// Value placed in the `unique` field of the primary key template, so
/// that the gkey primary key is distinct from other storage keys
/// derived from the same hierarchy.
const PRIMARY_UNIQUE: &[u8] = b"gkey storage root key";

/// A TPM wrapped ECC P-256 signing key.
pub struct SigningKey {
    /// Marshalled `TPM2B_PUBLIC` area of the key.
    pub public: Vec<u8>,
    /// Private area of the key, encrypted by the TPM with the primary
    /// key.  Useless outside of the TPM that created it.
    pub private: Vec<u8>,
    /// Affine X coordinate of the public point, big endian.
    pub x: [u8; 32],
    /// Affine Y coordinate of the public point, big endian.
    pub y: [u8; 32],
}

/// A TPM sealed data object.
pub struct SealedBlob {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

/// A connection to the TPM with the gkey primary key loaded.
pub struct Tpm {
    ctx: Context,
    primary: KeyHandle,
    fingerprint: [u8; 32],
}

/// Return the TCTI configuration string to use: the explicit one if
/// given, otherwise the `GKEY_TCTI`, `TPM2TOOLS_TCTI` or `TCTI`
/// environment variables, otherwise [`DEFAULT_TCTI`].
pub fn tcti_from_environment(explicit: Option<&str>) -> String {
    if let Some(tcti) = explicit {
        return tcti.to_string();
    }
    for var in ["GKEY_TCTI", "TPM2TOOLS_TCTI", "TCTI"] {
        if let Ok(value) = std::env::var(var) {
            if !value.is_empty() {
                return value;
            }
        }
    }
    DEFAULT_TCTI.to_string()
}

fn primary_template() -> Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()?;
    let parameters = PublicEccParametersBuilder::new_restricted_decryption_key(
        SymmetricDefinitionObject::AES_128_CFB,
        EccCurve::NistP256,
    )
    .build()?;
    let mut unique = [0u8; 32];
    unique.copy_from_slice(&Sha256::digest(PRIMARY_UNIQUE));
    let unique = EccPoint::new(unique.to_vec().try_into()?, Default::default());
    Ok(PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(parameters)
        .with_ecc_unique_identifier(unique)
        .build()?)
}

fn signing_key_template() -> Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_sign_encrypt(true)
        .build()?;
    let parameters = PublicEccParametersBuilder::new_unrestricted_signing_key(
        EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
        EccCurve::NistP256,
    )
    .build()?;
    Ok(PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(parameters)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()?)
}

fn sealed_data_template() -> Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .build()?;
    Ok(PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Default::default())
        .build()?)
}

/// Left pad a big endian integer to 32 bytes.
fn coordinate(value: &[u8]) -> Result<[u8; 32]> {
    if value.len() > 32 {
        return Err(Error::Generic(
            "TPM returned an oversized ECC coordinate".into(),
        ));
    }
    let mut out = [0u8; 32];
    out[32 - value.len()..].copy_from_slice(value);
    Ok(out)
}

fn public_point(public: Public) -> Result<([u8; 32], [u8; 32])> {
    match PublicKey::try_from(public)? {
        PublicKey::Ecc { x, y } => Ok((coordinate(&x)?, coordinate(&y)?)),
        PublicKey::Rsa(_) => Err(Error::Generic("TPM returned an RSA key".into())),
    }
}

/// Encode an ECDSA signature as the ASN.1 DER `Ecdsa-Sig-Value`
/// sequence that WebAuthn expects.
pub fn der_signature(r: &[u8], s: &[u8]) -> Vec<u8> {
    fn integer(out: &mut Vec<u8>, value: &[u8]) {
        let mut value = value;
        while value.len() > 1 && value[0] == 0 {
            value = &value[1..];
        }
        let pad = value.first().is_some_and(|b| b & 0x80 != 0) || value.is_empty();
        out.push(0x02);
        out.push((value.len() + pad as usize) as u8);
        if pad {
            out.push(0);
        }
        out.extend_from_slice(value);
    }
    let mut body = Vec::with_capacity(72);
    integer(&mut body, r);
    integer(&mut body, s);
    let mut out = Vec::with_capacity(body.len() + 2);
    out.push(0x30);
    out.push(body.len() as u8);
    out.extend_from_slice(&body);
    out
}

impl Tpm {
    /// Open a connection to the TPM described by `tcti` and derive
    /// the gkey primary key.
    pub fn open(tcti: &str) -> Result<Tpm> {
        let conf = TctiNameConf::from_str(tcti)
            .map_err(|e| Error::Generic(format!("invalid TCTI '{tcti}': {e}")))?;
        let mut ctx = Context::new(conf)
            .map_err(|e| Error::Generic(format!("cannot connect to TPM using '{tcti}': {e}")))?;
        let template = primary_template()?;
        let primary = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(Hierarchy::Owner, template, None, None, None, None)
            })
            .map_err(|e| {
                let message = e.to_string();
                let hint = if message.contains("auth") {
                    " (is the owner hierarchy protected by a password?)"
                } else {
                    ""
                };
                Error::Generic(format!(
                    "cannot create the storage primary key{hint}: {message}"
                ))
            })?;
        let (x, y) = public_point(primary.out_public)?;
        let mut hash = Sha256::new();
        hash.update(x);
        hash.update(y);
        let fingerprint = hash.finalize().into();
        let mut tpm = Tpm {
            ctx,
            primary: primary.key_handle,
            fingerprint,
        };
        tpm.start_session()?;
        Ok(tpm)
    }

    /// Start an HMAC session salted with the primary key and make it
    /// the session used to authorize every following command.
    fn start_session(&mut self) -> Result<()> {
        let session = self
            .ctx
            .start_auth_session(
                Some(self.primary),
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )?
            .ok_or_else(|| Error::Generic("TPM did not start an auth session".into()))?;
        let (attributes, mask) = SessionAttributesBuilder::new()
            .with_continue_session(true)
            .with_decrypt(true)
            .with_encrypt(true)
            .build();
        self.ctx.tr_sess_set_attributes(session, attributes, mask)?;
        self.ctx.set_sessions((Some(session), None, None));
        Ok(())
    }

    /// A digest of the public part of the primary key.  It changes if
    /// and only if the owner hierarchy seed changes (for instance when
    /// the TPM is cleared), which makes every key created earlier
    /// unusable.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Return `len` random bytes from the TPM's random number
    /// generator.
    pub fn random(&mut self, len: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let chunk = (len - out.len()).min(32);
            let digest = self
                .ctx
                .execute_without_session(|ctx| ctx.get_random(chunk))?;
            out.extend_from_slice(digest.value());
        }
        out.truncate(len);
        Ok(out)
    }

    /// Generate a new P-256 signing key inside the TPM.
    pub fn create_signing_key(&mut self) -> Result<SigningKey> {
        let created = self.ctx.create(
            self.primary,
            signing_key_template()?,
            None,
            None,
            None,
            None,
        )?;
        let public = created.out_public.marshall()?;
        let private = created.out_private.value().to_vec();
        let (x, y) = public_point(created.out_public)?;
        Ok(SigningKey {
            public,
            private,
            x,
            y,
        })
    }

    fn load(&mut self, public: &[u8], private: &[u8]) -> Result<KeyHandle> {
        let public = Public::unmarshall(public)?;
        let private = Private::try_from(private.to_vec())?;
        Ok(self.ctx.load(self.primary, private, public)?)
    }

    fn flush(&mut self, handle: KeyHandle) {
        if let Err(err) = self.ctx.flush_context(ObjectHandle::from(handle)) {
            log::warn!("cannot flush TPM object: {err}");
        }
    }

    /// Sign the SHA-256 `digest` with a key previously created by
    /// [`Tpm::create_signing_key`].  Returns a DER encoded ECDSA
    /// signature.
    pub fn sign(&mut self, public: &[u8], private: &[u8], digest: &[u8; 32]) -> Result<Vec<u8>> {
        let handle = self.load(public, private)?;
        let validation = HashcheckTicket::try_from(TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        });
        let result = validation.map_err(Error::from).and_then(|validation| {
            Ok(self.ctx.sign(
                handle,
                Digest::try_from(digest.to_vec())?,
                SignatureScheme::Null,
                validation,
            )?)
        });
        self.flush(handle);
        match result? {
            Signature::EcDsa(signature) => Ok(der_signature(
                signature.signature_r().value(),
                signature.signature_s().value(),
            )),
            _ => Err(Error::Generic("TPM returned a non ECDSA signature".into())),
        }
    }

    /// Seal `data` (at most 128 bytes) to this TPM.
    pub fn seal(&mut self, data: &[u8]) -> Result<SealedBlob> {
        let created = self.ctx.create(
            self.primary,
            sealed_data_template()?,
            None,
            Some(SensitiveData::try_from(data.to_vec())?),
            None,
            None,
        )?;
        Ok(SealedBlob {
            public: created.out_public.marshall()?,
            private: created.out_private.value().to_vec(),
        })
    }

    /// Recover data sealed with [`Tpm::seal`].
    pub fn unseal(&mut self, blob: &SealedBlob) -> Result<Zeroizing<Vec<u8>>> {
        let handle = self.load(&blob.public, &blob.private)?;
        let result = self.ctx.unseal(ObjectHandle::from(handle));
        self.flush(handle);
        Ok(Zeroizing::new(result?.value().to_vec()))
    }

    /// Return a human readable description of the TPM manufacturer.
    pub fn vendor(&mut self) -> String {
        tss_esapi::utils::get_tpm_vendor(&mut self.ctx).unwrap_or_else(|_| "unknown".into())
    }
}

impl Drop for Tpm {
    fn drop(&mut self) {
        if let Some(session) = self.ctx.sessions().0 {
            self.ctx.clear_sessions();
            let handle = tss_esapi::handles::SessionHandle::from(session);
            let _ = self.ctx.flush_context(handle.into());
        }
        let primary = self.primary;
        self.flush(primary);
    }
}

#[cfg(test)]
mod tests {
    use super::der_signature;

    #[test]
    fn der_encoding_pads_and_strips() {
        let r = [0x80u8; 32];
        let mut s = [0u8; 32];
        s[31] = 1;
        let der = der_signature(&r, &s);
        assert_eq!(der[0], 0x30);
        assert_eq!(der[2], 0x02);
        assert_eq!(der[3], 33);
        assert_eq!(der[4], 0x00);
        assert_eq!(&der[der.len() - 3..], &[0x02, 0x01, 0x01]);
        assert_eq!(der[1] as usize, der.len() - 2);
    }
}
