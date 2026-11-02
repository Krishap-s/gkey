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

//! The on disk credential store.
//!
//! The store is a single CBOR file in the user's data directory
//! (`$XDG_DATA_HOME/gkey/keystore`).  It holds:
//!
//! * a 256-bit AES key sealed to the TPM, which only this TPM can
//!   unseal;
//! * the list of credentials, encrypted and authenticated with that
//!   key using AES-256-GCM.
//!
//! Each credential carries its TPM wrapped private key, so the file is
//! worthless on another machine, and it cannot be read or modified
//! without detection on this one without access to the TPM.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use zeroize::Zeroizing;

use crate::prelude::*;
use crate::tpm::{SealedBlob, Tpm};

const FORMAT_VERSION: u32 = 1;
const KEYSTORE_FILE: &str = "keystore";
const LOCK_FILE: &str = "keystore.lock";
/// Additional authenticated data binding the ciphertext to its use.
const AAD: &[u8] = b"gkey credential list v1";

/// A WebAuthn credential.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Credential {
    /// Credential ID handed to the relying party.
    pub id: ByteBuf,
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_id: ByteBuf,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    /// Whether the credential is discoverable (a resident key).
    pub discoverable: bool,
    /// Uncompressed SEC1 encoding of the P-256 public key.
    pub public_key: ByteBuf,
    /// Marshalled TPM public area of the key.
    pub tpm_public: ByteBuf,
    /// TPM wrapped private area of the key.
    pub tpm_private: ByteBuf,
    pub sign_count: u32,
    /// Creation time, in seconds since the epoch.
    pub created: u64,
}

impl Credential {
    /// Hexadecimal representation of the credential ID.
    pub fn id_hex(&self) -> String {
        hex(&self.id)
    }
}

/// Format `bytes` as lower case hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Serialize, Deserialize)]
struct KeystoreFile {
    version: u32,
    /// Fingerprint of the TPM primary key the store was created with.
    primary: ByteBuf,
    sealed_public: ByteBuf,
    sealed_private: ByteBuf,
    nonce: ByteBuf,
    ciphertext: ByteBuf,
}

/// An open, locked keystore.  The lock is released when the value is
/// dropped.
pub struct Keystore {
    dir: PathBuf,
    _lock: File,
    sealed: SealedBlob,
    primary: [u8; 32],
    key: Zeroizing<Vec<u8>>,
    pub credentials: Vec<Credential>,
}

/// Return the default keystore directory: `$GKEY_KEYSTORE`, or
/// `$XDG_DATA_HOME/gkey`, or `$HOME/.local/share/gkey`.
pub fn default_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("GKEY_KEYSTORE").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(dir).join("gkey"));
    }
    match std::env::var_os("HOME").filter(|d| !d.is_empty()) {
        Some(home) => Ok(PathBuf::from(home).join(".local/share/gkey")),
        None => Err(Error::Keystore(
            "cannot determine the keystore directory; set HOME or XDG_DATA_HOME".into(),
        )),
    }
}

fn lock(dir: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(dir.join(LOCK_FILE))?;
    // SAFETY: flock only operates on the open descriptor.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(file)
}

fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|e| Error::Keystore(e.to_string()))?;
    Ok(out)
}

impl Keystore {
    /// Whether a keystore exists in `dir`.
    pub fn exists(dir: &Path) -> bool {
        dir.join(KEYSTORE_FILE).exists()
    }

    /// Create a new, empty keystore in `dir`.  Fails if one exists.
    pub fn create(dir: &Path, tpm: &mut Tpm) -> Result<Keystore> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let lock = lock(dir)?;
        if Self::exists(dir) {
            return Err(Error::Keystore(format!(
                "a keystore already exists in '{}'",
                dir.display()
            )));
        }
        let key = Zeroizing::new(tpm.random(32)?);
        let sealed = tpm.seal(&key)?;
        let mut keystore = Keystore {
            dir: dir.to_path_buf(),
            _lock: lock,
            sealed,
            primary: tpm.fingerprint(),
            key,
            credentials: Vec::new(),
        };
        keystore.save(tpm)?;
        Ok(keystore)
    }

    /// Open and decrypt the keystore in `dir`.
    pub fn open(dir: &Path, tpm: &mut Tpm) -> Result<Keystore> {
        let lock = lock(dir).map_err(|e| match e {
            Error::IO(err) if err.kind() == ErrorKind::NotFound => no_keystore(dir),
            other => other,
        })?;
        let raw = match fs::read(dir.join(KEYSTORE_FILE)) {
            Ok(raw) => raw,
            Err(err) if err.kind() == ErrorKind::NotFound => return Err(no_keystore(dir)),
            Err(err) => return Err(err.into()),
        };
        let file: KeystoreFile = ciborium::from_reader(raw.as_slice())
            .map_err(|e| Error::Keystore(format!("corrupt keystore: {e}")))?;
        if file.version != FORMAT_VERSION {
            return Err(Error::Keystore(format!(
                "unsupported keystore format version {}",
                file.version
            )));
        }
        if file.primary.as_slice() != tpm.fingerprint() {
            return Err(Error::Keystore(
                "the keystore was created with a different TPM, or the TPM \
                 has been cleared since; its credentials cannot be used"
                    .into(),
            ));
        }
        let sealed = SealedBlob {
            public: file.sealed_public.into_vec(),
            private: file.sealed_private.into_vec(),
        };
        let key = tpm.unseal(&sealed)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| Error::Keystore("sealed key has the wrong size".into()))?;
        let nonce: [u8; 12] = file
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| Error::Keystore("corrupt keystore: bad nonce".into()))?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &Nonce::from(nonce),
                    Payload {
                        msg: &file.ciphertext,
                        aad: AAD,
                    },
                )
                .map_err(|_| Error::Keystore("keystore failed integrity check".into()))?,
        );
        let credentials = ciborium::from_reader(plaintext.as_slice())
            .map_err(|e| Error::Keystore(format!("corrupt credential list: {e}")))?;
        Ok(Keystore {
            dir: dir.to_path_buf(),
            _lock: lock,
            sealed,
            primary: tpm.fingerprint(),
            key,
            credentials,
        })
    }

    /// Open the keystore in `dir`, creating it if it does not exist.
    pub fn open_or_create(dir: &Path, tpm: &mut Tpm) -> Result<Keystore> {
        if Self::exists(dir) {
            Self::open(dir, tpm)
        } else {
            Self::create(dir, tpm)
        }
    }

    /// The directory holding the keystore.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Encrypt and atomically write the keystore back to disk.
    pub fn save(&mut self, tpm: &mut Tpm) -> Result<()> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| Error::Keystore("sealed key has the wrong size".into()))?;
        let nonce: [u8; 12] = tpm.random(12)?.try_into().expect("12 random bytes");
        let plaintext = Zeroizing::new(to_cbor(&self.credentials)?);
        let ciphertext = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &plaintext,
                    aad: AAD,
                },
            )
            .map_err(|_| Error::Keystore("encryption failed".into()))?;
        let file = KeystoreFile {
            version: FORMAT_VERSION,
            primary: ByteBuf::from(self.primary.to_vec()),
            sealed_public: ByteBuf::from(self.sealed.public.clone()),
            sealed_private: ByteBuf::from(self.sealed.private.clone()),
            nonce: ByteBuf::from(nonce.to_vec()),
            ciphertext: ByteBuf::from(ciphertext),
        };
        let encoded = to_cbor(&file)?;
        let temporary = self.dir.join(format!("{KEYSTORE_FILE}.tmp"));
        {
            let mut out = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(&temporary)?;
            out.write_all(&encoded)?;
            out.sync_all()?;
        }
        fs::rename(&temporary, self.dir.join(KEYSTORE_FILE))?;
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// Find a credential by ID.
    pub fn find(&self, id: &[u8]) -> Option<usize> {
        self.credentials.iter().position(|c| c.id.as_slice() == id)
    }

    /// Return the indexes of the credentials whose hexadecimal ID
    /// starts with `prefix`.
    pub fn find_prefix(&self, prefix: &str) -> Vec<usize> {
        let prefix = prefix.to_ascii_lowercase();
        self.credentials
            .iter()
            .enumerate()
            .filter(|(_, c)| c.id_hex().starts_with(&prefix))
            .map(|(i, _)| i)
            .collect()
    }
}

fn no_keystore(dir: &Path) -> Error {
    Error::Keystore(format!(
        "no keystore in '{}'; run 'gkey init' to create one",
        dir.display()
    ))
}
