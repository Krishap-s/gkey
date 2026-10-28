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

//! The CTAP 2.0 authenticator (Client to Authenticator Protocol,
//! section 5).
//!
//! Supported commands are authenticatorMakeCredential,
//! authenticatorGetAssertion, authenticatorGetNextAssertion,
//! authenticatorGetInfo and authenticatorReset.  Credentials use ES256
//! (ECDSA over P-256 with SHA-256); their private keys live in the
//! TPM.  The authenticator has built-in user verification (see
//! [`crate::verify`]) and does not implement clientPIN.

use std::collections::VecDeque;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ciborium::Value;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};

use tokio::sync::oneshot;

use crate::ctaphid::{Request, Submit, STATUS_PROCESSING, STATUS_UPNEEDED};
use crate::keystore::{self, Credential, Keystore};
use crate::prelude::*;
use crate::system::{User, UserSource};
use crate::tpm::Tpm;
use crate::verify::{Kind, Outcome, Verifier};

pub const CMD_MAKE_CREDENTIAL: u8 = 0x01;
pub const CMD_GET_ASSERTION: u8 = 0x02;
pub const CMD_GET_INFO: u8 = 0x04;
pub const CMD_CLIENT_PIN: u8 = 0x06;
pub const CMD_RESET: u8 = 0x07;
pub const CMD_GET_NEXT_ASSERTION: u8 = 0x08;

pub const CTAP2_OK: u8 = 0x00;
pub const CTAP1_ERR_INVALID_COMMAND: u8 = 0x01;
pub const CTAP1_ERR_INVALID_PARAMETER: u8 = 0x02;
pub const CTAP2_ERR_CBOR_UNEXPECTED_TYPE: u8 = 0x11;
pub const CTAP2_ERR_INVALID_CBOR: u8 = 0x12;
pub const CTAP2_ERR_MISSING_PARAMETER: u8 = 0x14;
pub const CTAP2_ERR_CREDENTIAL_EXCLUDED: u8 = 0x19;
pub const CTAP2_ERR_UNSUPPORTED_ALGORITHM: u8 = 0x26;
pub const CTAP2_ERR_OPERATION_DENIED: u8 = 0x27;
pub const CTAP2_ERR_INVALID_OPTION: u8 = 0x2c;
pub const CTAP2_ERR_KEEPALIVE_CANCEL: u8 = 0x2d;
pub const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2e;
pub const CTAP2_ERR_NOT_ALLOWED: u8 = 0x30;
pub const CTAP2_ERR_PIN_AUTH_INVALID: u8 = 0x33;
pub const CTAP2_ERR_PIN_NOT_SET: u8 = 0x35;
pub const CTAP2_ERR_OTHER: u8 = 0x7f;

/// Authenticator Attestation GUID identifying gkey.
pub const AAGUID: [u8; 16] = [
    0x09, 0x0a, 0xa3, 0x90, 0x0a, 0x48, 0x48, 0x06, 0xb7, 0x99, 0x22, 0xb1, 0x7d, 0x2a, 0x5c, 0x0d,
];

/// COSE algorithm identifier of ES256.
const COSE_ES256: i64 = -7;
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;
const CREDENTIAL_ID_SIZE: usize = 16;
const MAX_MESSAGE_SIZE: i64 = crate::ctaphid::MAX_MESSAGE_SIZE as i64;
/// How long the platform has to fetch the remaining assertions.
const NEXT_ASSERTION_TIMEOUT: Duration = Duration::from_secs(30);

type CtapResult<T> = std::result::Result<T, u8>;

/// Log an internal error and turn it into a CTAP status.
fn internal(err: Error) -> u8 {
    log::error!("{err}");
    CTAP2_ERR_OTHER
}

fn int(value: i64) -> Value {
    Value::Integer(value.into())
}

fn text(value: &str) -> Value {
    Value::Text(value.to_string())
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

fn get_int(map: &[(Value, Value)], key: i64) -> Option<&Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Integer(i) if i128::from(*i) == key as i128))
        .map(|(_, v)| v)
}

fn get_text<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
        .map(|(_, v)| v)
}

fn as_map(value: &Value) -> CtapResult<&[(Value, Value)]> {
    match value {
        Value::Map(map) => Ok(map),
        _ => Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
    }
}

fn as_bytes(value: &Value) -> CtapResult<&[u8]> {
    match value {
        Value::Bytes(b) => Ok(b),
        _ => Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
    }
}

fn as_text(value: &Value) -> CtapResult<&str> {
    match value {
        Value::Text(t) => Ok(t),
        _ => Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
    }
}

fn as_array(value: &Value) -> CtapResult<&[Value]> {
    match value {
        Value::Array(a) => Ok(a),
        _ => Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
    }
}

fn as_bool(value: &Value) -> CtapResult<bool> {
    match value {
        Value::Bool(b) => Ok(*b),
        _ => Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
    }
}

fn optional_text(map: &[(Value, Value)], key: &str) -> CtapResult<Option<String>> {
    get_text(map, key)
        .map(|v| as_text(v).map(str::to_string))
        .transpose()
}

fn client_data_hash(value: Option<&Value>) -> CtapResult<[u8; 32]> {
    let hash = as_bytes(value.ok_or(CTAP2_ERR_MISSING_PARAMETER)?)?;
    hash.try_into().map_err(|_| CTAP1_ERR_INVALID_PARAMETER)
}

/// Parse a list of PublicKeyCredentialDescriptors, keeping the IDs of
/// the "public-key" ones.
fn credential_ids(value: &Value) -> CtapResult<Vec<Vec<u8>>> {
    let mut ids = Vec::new();
    for descriptor in as_array(value)? {
        let descriptor = as_map(descriptor)?;
        let kind = as_text(get_text(descriptor, "type").ok_or(CTAP2_ERR_MISSING_PARAMETER)?)?;
        let id = as_bytes(get_text(descriptor, "id").ok_or(CTAP2_ERR_MISSING_PARAMETER)?)?;
        if kind == "public-key" {
            ids.push(id.to_vec());
        }
    }
    Ok(ids)
}

/// Options common to makeCredential and getAssertion.
struct Options {
    rk: bool,
    up: bool,
    uv: bool,
}

fn options(value: Option<&Value>) -> CtapResult<Options> {
    let mut options = Options {
        rk: false,
        up: true,
        uv: false,
    };
    if let Some(value) = value {
        for (key, value) in as_map(value)? {
            match as_text(key)? {
                "rk" => options.rk = as_bool(value)?,
                "up" => options.up = as_bool(value)?,
                "uv" => options.uv = as_bool(value)?,
                _ => {}
            }
        }
    }
    Ok(options)
}

fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("CBOR encoding into memory cannot fail");
    out
}

/// Encode a P-256 public key as a COSE_Key (RFC 8152, section 13.1.1).
pub fn cose_key(public_key: &[u8]) -> Vec<u8> {
    let (x, y) = (&public_key[1..33], &public_key[33..65]);
    encode(&Value::Map(vec![
        (int(1), int(2)),          // kty: EC2
        (int(3), int(COSE_ES256)), // alg: ES256
        (int(-1), int(1)),         // crv: P-256
        (int(-2), bytes(x)),       // x
        (int(-3), bytes(y)),       // y
    ]))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// State kept between getAssertion and getNextAssertion.
struct PendingAssertions {
    uid: u32,
    rp_id: String,
    client_data_hash: [u8; 32],
    flags: u8,
    ids: VecDeque<Vec<u8>>,
    started: Instant,
}

/// Per request context supplied by the transport.
pub struct RequestContext<'a> {
    pub cancel: &'a AtomicBool,
    pub status: &'a AtomicU8,
}

/// The authenticator state machine.
pub struct Authenticator {
    tpm: Tpm,
    state_dir: PathBuf,
    users: UserSource,
    verifier: Verifier,
    pending: Option<PendingAssertions>,
}

impl Authenticator {
    /// Create an authenticator keeping the keystores of the users in
    /// `state_dir`, serving the users that `users` designates.
    pub fn new(tpm: Tpm, state_dir: PathBuf, users: UserSource, verifier: Verifier) -> Self {
        Authenticator {
            tpm,
            state_dir,
            users,
            verifier,
            pending: None,
        }
    }

    /// Process one CTAP2 request (command byte followed by CBOR) and
    /// return the response (status byte possibly followed by CBOR).
    pub fn handle(&mut self, request: &[u8], ctx: &RequestContext) -> Vec<u8> {
        let Some((&command, parameters)) = request.split_first() else {
            return vec![CTAP1_ERR_INVALID_COMMAND];
        };
        log::debug!("CTAP2 command {command:#04x}");
        if command != CMD_GET_NEXT_ASSERTION {
            self.pending = None;
        }
        let parameters = if parameters.is_empty() {
            Ok(None)
        } else {
            match ciborium::from_reader::<Value, _>(parameters) {
                Ok(Value::Map(map)) => Ok(Some(map)),
                Ok(_) => Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
                Err(_) => Err(CTAP2_ERR_INVALID_CBOR),
            }
        };
        let result = parameters.and_then(|parameters| {
            let parameters = parameters.unwrap_or_default();
            match command {
                CMD_MAKE_CREDENTIAL => self.make_credential(&parameters, ctx),
                CMD_GET_ASSERTION => self.get_assertion(&parameters, ctx),
                CMD_GET_NEXT_ASSERTION => self.get_next_assertion(),
                CMD_GET_INFO => Ok(Some(self.get_info())),
                CMD_RESET => self.reset(ctx),
                _ => Err(CTAP1_ERR_INVALID_COMMAND),
            }
        });
        match result {
            Ok(Some(value)) => {
                let mut out = vec![CTAP2_OK];
                out.extend_from_slice(&encode(&value));
                out
            }
            Ok(None) => vec![CTAP2_OK],
            Err(status) => {
                log::debug!("CTAP2 command {command:#04x} failed with {status:#04x}");
                vec![status]
            }
        }
    }

    /// The user to process the current request for.
    fn user(&self) -> CtapResult<User> {
        match self.users.current() {
            Ok(Some(user)) => Ok(user),
            Ok(None) => {
                log::warn!("request refused: nobody is using the seat");
                Err(CTAP2_ERR_OPERATION_DENIED)
            }
            Err(err) => Err(internal(err)),
        }
    }

    fn consent(
        &self,
        kind: Kind,
        description: &str,
        user: &User,
        ctx: &RequestContext,
    ) -> CtapResult<()> {
        ctx.status.store(STATUS_UPNEEDED, Ordering::Relaxed);
        let outcome = self.verifier.ask(kind, description, user, ctx.cancel);
        ctx.status.store(STATUS_PROCESSING, Ordering::Relaxed);
        match outcome {
            Ok(Outcome::Granted) => Ok(()),
            Ok(Outcome::Denied) => Err(CTAP2_ERR_OPERATION_DENIED),
            Ok(Outcome::Cancelled) => Err(CTAP2_ERR_KEEPALIVE_CANCEL),
            Err(err) => {
                log::error!("cannot obtain user consent: {err}");
                Err(CTAP2_ERR_OPERATION_DENIED)
            }
        }
    }

    fn user_dir(&self, uid: u32) -> PathBuf {
        keystore::user_dir(&self.state_dir, uid)
    }

    fn open_keystore(&mut self, user: &User) -> CtapResult<Keystore> {
        let dir = self.user_dir(user.uid);
        Keystore::open_or_create(&dir, &mut self.tpm).map_err(internal)
    }

    /// Handle the zero length pinAuth that platforms send to make the
    /// user pick an authenticator (CTAP 2.0, section 5.1, step 2).
    fn pin_auth(&self, value: Option<&Value>, user: &User, ctx: &RequestContext) -> CtapResult<()> {
        match value {
            None => Ok(()),
            Some(value) if as_bytes(value)?.is_empty() => {
                self.consent(Kind::Presence, "Use gkey as your security key?", user, ctx)?;
                Err(CTAP2_ERR_PIN_NOT_SET)
            }
            Some(_) => Err(CTAP2_ERR_PIN_AUTH_INVALID),
        }
    }

    fn make_credential(
        &mut self,
        parameters: &[(Value, Value)],
        ctx: &RequestContext,
    ) -> CtapResult<Option<Value>> {
        // Only needed for attestation formats other than "none".
        let _client_data_hash = client_data_hash(get_int(parameters, 1))?;
        let rp = as_map(get_int(parameters, 2).ok_or(CTAP2_ERR_MISSING_PARAMETER)?)?;
        let user_entity = as_map(get_int(parameters, 3).ok_or(CTAP2_ERR_MISSING_PARAMETER)?)?;
        let algorithms = as_array(get_int(parameters, 4).ok_or(CTAP2_ERR_MISSING_PARAMETER)?)?;
        let exclude = get_int(parameters, 5).map(credential_ids).transpose()?;
        let options = options(get_int(parameters, 7))?;
        let user = self.user()?;
        self.pin_auth(get_int(parameters, 8), &user, ctx)?;

        let rp_id = as_text(get_text(rp, "id").ok_or(CTAP2_ERR_MISSING_PARAMETER)?)?.to_string();
        let rp_name = optional_text(rp, "name")?;
        let user_id =
            as_bytes(get_text(user_entity, "id").ok_or(CTAP2_ERR_MISSING_PARAMETER)?)?.to_vec();
        let user_name = optional_text(user_entity, "name")?;
        let user_display_name = optional_text(user_entity, "displayName")?;

        let mut supported = false;
        for algorithm in algorithms {
            let algorithm = as_map(algorithm)?;
            let kind = as_text(get_text(algorithm, "type").ok_or(CTAP2_ERR_MISSING_PARAMETER)?)?;
            let alg = match get_text(algorithm, "alg").ok_or(CTAP2_ERR_MISSING_PARAMETER)? {
                Value::Integer(i) => i128::from(*i),
                _ => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            };
            if kind == "public-key" && alg == COSE_ES256 as i128 {
                supported = true;
            }
        }
        if !supported {
            return Err(CTAP2_ERR_UNSUPPORTED_ALGORITHM);
        }
        if !options.up {
            return Err(CTAP2_ERR_INVALID_OPTION);
        }

        if let Some(exclude) = exclude {
            let keystore = self.open_keystore(&user)?;
            let excluded = exclude.iter().any(|id| {
                keystore
                    .find(id)
                    .is_some_and(|i| keystore.credentials[i].rp_id == rp_id)
            });
            drop(keystore);
            if excluded {
                self.consent(
                    Kind::Presence,
                    &format!("You already have a passkey for {rp_id} in gkey."),
                    &user,
                    ctx,
                )?;
                return Err(CTAP2_ERR_CREDENTIAL_EXCLUDED);
            }
        }

        let account = user_name
            .as_deref()
            .or(user_display_name.as_deref())
            .unwrap_or("unnamed account");
        let description = format!("Create a passkey for {rp_id}?\n\nAccount: {account}");
        let kind = if options.uv {
            Kind::Verification
        } else {
            Kind::Presence
        };
        self.consent(kind, &description, &user, ctx)?;

        let mut keystore = self.open_keystore(&user)?;
        let key = keystore
            .create_credential_key(&mut self.tpm)
            .map_err(internal)?;
        let id = self.tpm.random(CREDENTIAL_ID_SIZE).map_err(internal)?;
        let mut public_key = Vec::with_capacity(65);
        public_key.push(0x04);
        public_key.extend_from_slice(&key.x);
        public_key.extend_from_slice(&key.y);
        let credential = Credential {
            id: ByteBuf::from(id.clone()),
            rp_id: rp_id.clone(),
            rp_name,
            user_id: ByteBuf::from(user_id.clone()),
            user_name,
            user_display_name,
            discoverable: options.rk,
            public_key: ByteBuf::from(public_key.clone()),
            tpm_public: ByteBuf::from(key.public),
            tpm_private: ByteBuf::from(key.private),
            sign_count: 0,
            created: now(),
        };

        if options.rk {
            // A new discoverable credential replaces the one held for
            // the same account.
            keystore.credentials.retain(|c| {
                !(c.discoverable && c.rp_id == rp_id && c.user_id.as_slice() == user_id)
            });
        }
        keystore.credentials.push(credential);
        keystore.save(&mut self.tpm).map_err(internal)?;
        log::info!(
            "created credential {} for {rp_id} for user {}",
            keystore::hex(&id),
            user.uid
        );

        let mut flags = FLAG_UP | FLAG_AT;
        if options.uv {
            flags |= FLAG_UV;
        }
        let mut auth_data = Vec::with_capacity(256);
        auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        auth_data.push(flags);
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        auth_data.extend_from_slice(&AAGUID);
        auth_data.extend_from_slice(&(id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&id);
        auth_data.extend_from_slice(&cose_key(&public_key));

        Ok(Some(Value::Map(vec![
            (int(1), text("none")),
            (int(2), Value::Bytes(auth_data)),
            (int(3), Value::Map(vec![])),
        ])))
    }

    fn get_assertion(
        &mut self,
        parameters: &[(Value, Value)],
        ctx: &RequestContext,
    ) -> CtapResult<Option<Value>> {
        let rp_id =
            as_text(get_int(parameters, 1).ok_or(CTAP2_ERR_MISSING_PARAMETER)?)?.to_string();
        let client_data_hash = client_data_hash(get_int(parameters, 2))?;
        let allow = get_int(parameters, 3).map(credential_ids).transpose()?;
        let options = options(get_int(parameters, 5))?;
        let user = self.user()?;
        self.pin_auth(get_int(parameters, 6), &user, ctx)?;
        if options.rk {
            return Err(CTAP2_ERR_INVALID_OPTION);
        }

        let keystore = self.open_keystore(&user)?;
        let allow = allow.filter(|ids| !ids.is_empty());
        let mut matches: Vec<&Credential> = match &allow {
            Some(ids) => ids
                .iter()
                .filter_map(|id| keystore.find(id))
                .map(|i| &keystore.credentials[i])
                .filter(|c| c.rp_id == rp_id)
                .take(1)
                .collect(),
            None => keystore
                .credentials
                .iter()
                .filter(|c| c.discoverable && c.rp_id == rp_id)
                .collect(),
        };
        if matches.is_empty() {
            return Err(CTAP2_ERR_NO_CREDENTIALS);
        }
        matches.sort_by_key(|c| std::cmp::Reverse(c.created));
        let ids: VecDeque<Vec<u8>> = matches.iter().map(|c| c.id.to_vec()).collect();
        let account = match matches.as_slice() {
            [only] => only
                .user_name
                .clone()
                .or_else(|| only.user_display_name.clone())
                .unwrap_or_else(|| "unnamed account".into()),
            many => format!("one of {} accounts", many.len()),
        };
        drop(keystore);

        let mut flags = 0;
        if options.uv {
            self.consent(
                Kind::Verification,
                &format!("Sign in to {rp_id}?\n\nAccount: {account}"),
                &user,
                ctx,
            )?;
            flags |= FLAG_UP | FLAG_UV;
        } else if options.up {
            self.consent(
                Kind::Presence,
                &format!("Sign in to {rp_id}?\n\nAccount: {account}"),
                &user,
                ctx,
            )?;
            flags |= FLAG_UP;
        }

        let mut pending = PendingAssertions {
            uid: user.uid,
            rp_id,
            client_data_hash,
            flags,
            ids,
            started: Instant::now(),
        };
        let count = pending.ids.len();
        let first = pending.ids.pop_front().expect("at least one credential");
        let mut response = self.assert(&pending, &first, allow.is_none())?;
        if allow.is_none() && count > 1 {
            response.push((int(5), int(count as i64)));
            self.pending = Some(pending);
        }
        Ok(Some(Value::Map(response)))
    }

    fn get_next_assertion(&mut self) -> CtapResult<Option<Value>> {
        let Some(mut pending) = self.pending.take() else {
            return Err(CTAP2_ERR_NOT_ALLOWED);
        };
        if pending.started.elapsed() > NEXT_ASSERTION_TIMEOUT || self.user()?.uid != pending.uid {
            return Err(CTAP2_ERR_NOT_ALLOWED);
        }
        let Some(id) = pending.ids.pop_front() else {
            return Err(CTAP2_ERR_NOT_ALLOWED);
        };
        let response = self.assert(&pending, &id, true)?;
        if !pending.ids.is_empty() {
            self.pending = Some(pending);
        }
        Ok(Some(Value::Map(response)))
    }

    /// Produce the assertion for credential `id`, bumping its
    /// signature counter.
    fn assert(
        &mut self,
        pending: &PendingAssertions,
        id: &[u8],
        include_user: bool,
    ) -> CtapResult<Vec<(Value, Value)>> {
        let dir = self.user_dir(pending.uid);
        let mut keystore = Keystore::open(&dir, &mut self.tpm).map_err(internal)?;
        let index = keystore.find(id).ok_or(CTAP2_ERR_NO_CREDENTIALS)?;
        let credential = &mut keystore.credentials[index];
        if credential.rp_id != pending.rp_id {
            return Err(CTAP2_ERR_NO_CREDENTIALS);
        }
        credential.sign_count = credential.sign_count.wrapping_add(1);
        let credential = credential.clone();
        keystore.save(&mut self.tpm).map_err(internal)?;

        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&Sha256::digest(pending.rp_id.as_bytes()));
        auth_data.push(pending.flags);
        auth_data.extend_from_slice(&credential.sign_count.to_be_bytes());
        let mut hash = Sha256::new();
        hash.update(&auth_data);
        hash.update(pending.client_data_hash);
        let digest: [u8; 32] = hash.finalize().into();
        let signature = keystore
            .sign(&mut self.tpm, &credential, &digest)
            .map_err(internal)?;
        drop(keystore);
        log::info!(
            "signed assertion for {} with credential {}",
            pending.rp_id,
            credential.id_hex()
        );

        let mut response = vec![
            (
                int(1),
                Value::Map(vec![
                    (text("id"), bytes(&credential.id)),
                    (text("type"), text("public-key")),
                ]),
            ),
            (int(2), Value::Bytes(auth_data)),
            (int(3), Value::Bytes(signature)),
        ];
        if include_user && credential.discoverable {
            let mut user = vec![(text("id"), bytes(&credential.user_id))];
            // Identifying information requires user verification.
            if pending.flags & FLAG_UV != 0 {
                if let Some(name) = &credential.user_name {
                    user.push((text("name"), text(name)));
                }
                if let Some(name) = &credential.user_display_name {
                    user.push((text("displayName"), text(name)));
                }
            }
            response.push((int(4), Value::Map(user)));
        }
        Ok(response)
    }

    fn get_info(&self) -> Value {
        Value::Map(vec![
            (int(1), Value::Array(vec![text("FIDO_2_0")])),
            // Optional, but some clients insist on its presence.
            (int(2), Value::Array(vec![])),
            (int(3), bytes(&AAGUID)),
            (
                int(4),
                Value::Map(vec![
                    (text("rk"), Value::Bool(true)),
                    (text("up"), Value::Bool(true)),
                    (text("uv"), Value::Bool(true)),
                    (text("plat"), Value::Bool(false)),
                ]),
            ),
            (int(5), int(MAX_MESSAGE_SIZE)),
            (int(9), Value::Array(vec![text("usb")])),
            (
                int(10),
                Value::Array(vec![Value::Map(vec![
                    (text("alg"), int(COSE_ES256)),
                    (text("type"), text("public-key")),
                ])]),
            ),
        ])
    }

    fn reset(&mut self, ctx: &RequestContext) -> CtapResult<Option<Value>> {
        let user = self.user()?;
        self.consent(
            Kind::Verification,
            "Delete ALL your passkeys stored in gkey?\n\nThis cannot be undone.",
            &user,
            ctx,
        )?;
        let mut keystore = self.open_keystore(&user)?;
        keystore.credentials.clear();
        keystore.save(&mut self.tpm).map_err(internal)?;
        log::info!(
            "all credentials of user {} deleted by authenticatorReset",
            user.uid
        );
        Ok(None)
    }
}

/// Summary of a credential, as reported to management clients.
#[derive(Clone, Debug)]
pub struct CredentialSummary {
    pub id: String,
    pub rp_id: String,
    pub user_name: String,
    pub user_display_name: String,
    pub discoverable: bool,
    pub created: u64,
    pub sign_count: u32,
}

impl From<&Credential> for CredentialSummary {
    fn from(c: &Credential) -> Self {
        CredentialSummary {
            id: c.id_hex(),
            rp_id: c.rp_id.clone(),
            user_name: c.user_name.clone().unwrap_or_default(),
            user_display_name: c.user_display_name.clone().unwrap_or_default(),
            discoverable: c.discoverable,
            created: c.created,
            sign_count: c.sign_count,
        }
    }
}

/// Description of the authenticator, as reported to management
/// clients.
#[derive(Clone, Debug)]
pub struct Info {
    pub vendor: String,
    pub fingerprint: String,
    pub keystore: PathBuf,
    pub credentials: usize,
    pub discoverable: usize,
}

type Reply<T> = oneshot::Sender<std::result::Result<T, String>>;

/// A request from a management client, made on behalf of the user
/// `uid`.  The caller has already established who the client is and
/// what it may do.
pub enum Manage {
    List {
        uid: u32,
        reply: Reply<Vec<CredentialSummary>>,
    },
    /// Delete the credentials whose IDs start with each of `ids`.
    Delete {
        uid: u32,
        ids: Vec<String>,
        reply: Reply<Vec<CredentialSummary>>,
    },
    Info {
        uid: u32,
        reply: Reply<Info>,
    },
}

/// Work for the authenticator thread.
pub enum Job {
    Ctap(Request),
    Manage(Manage),
}

/// A queue to the authenticator thread.
#[derive(Clone)]
pub struct Jobs(mpsc::Sender<Job>);

impl Submit for Jobs {
    fn submit(&self, request: Request) -> bool {
        self.0.send(Job::Ctap(request)).is_ok()
    }
}

impl Jobs {
    /// Queue a management request; false if the authenticator is gone.
    pub fn manage(&self, request: Manage) -> bool {
        self.0.send(Job::Manage(request)).is_ok()
    }
}

fn list(keystore: Option<&Keystore>) -> Vec<CredentialSummary> {
    keystore
        .map(|k| k.credentials.iter().map(CredentialSummary::from).collect())
        .unwrap_or_default()
}

impl Authenticator {
    /// Open the keystore of `uid` if it exists, without creating it.
    fn existing_keystore(&mut self, uid: u32) -> Result<Option<Keystore>> {
        let dir = self.user_dir(uid);
        if !Keystore::exists(&dir) {
            return Ok(None);
        }
        Keystore::open(&dir, &mut self.tpm).map(Some)
    }

    /// Process a management request.
    pub fn manage(&mut self, request: Manage) {
        match request {
            Manage::List { uid, reply } => {
                let result = self
                    .existing_keystore(uid)
                    .map(|k| list(k.as_ref()))
                    .map_err(|e| e.to_string());
                let _ = reply.send(result);
            }
            Manage::Delete { uid, ids, reply } => {
                let _ = reply.send(self.delete(uid, &ids));
            }
            Manage::Info { uid, reply } => {
                let result = self.info(uid).map_err(|e| e.to_string());
                let _ = reply.send(result);
            }
        }
    }

    fn delete(
        &mut self,
        uid: u32,
        prefixes: &[String],
    ) -> std::result::Result<Vec<CredentialSummary>, String> {
        let Some(mut keystore) = self.existing_keystore(uid).map_err(|e| e.to_string())? else {
            return Err("no credentials".into());
        };
        let mut doomed = Vec::new();
        for prefix in prefixes {
            match keystore.find_prefix(prefix).as_slice() {
                [] => return Err(format!("no credential matches '{prefix}'")),
                [index] => doomed.push(*index),
                _ => return Err(format!("'{prefix}' matches several credentials")),
            }
        }
        doomed.sort_unstable();
        doomed.dedup();
        let mut deleted = Vec::new();
        for index in doomed.into_iter().rev() {
            deleted.push(CredentialSummary::from(&keystore.credentials.remove(index)));
        }
        keystore.save(&mut self.tpm).map_err(|e| e.to_string())?;
        for credential in &deleted {
            log::info!("user {uid} deleted credential {}", credential.id);
        }
        Ok(deleted)
    }

    fn info(&mut self, uid: u32) -> Result<Info> {
        let keystore = self.existing_keystore(uid)?;
        let credentials = list(keystore.as_ref());
        Ok(Info {
            vendor: self.tpm.vendor(),
            fingerprint: keystore::hex(&self.tpm.fingerprint()),
            keystore: self.user_dir(uid),
            discoverable: credentials.iter().filter(|c| c.discoverable).count(),
            credentials: credentials.len(),
        })
    }
}

/// A running authenticator thread.
pub struct Handle {
    sender: Option<Jobs>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Handle {
    /// A queue on which to submit requests.
    pub fn sender(&self) -> Jobs {
        self.sender.clone().expect("authenticator is running")
    }

    /// Wait for the authenticator to finish once every sender is gone,
    /// releasing its TPM resources.
    pub fn shutdown(mut self) {
        self.sender = None;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Start the authenticator on its own thread, keeping the keystores
/// of the users in `state_dir`.  The TPM connection is opened before
/// this returns.
pub fn spawn(
    tcti: String,
    state_dir: &Path,
    users: UserSource,
    verifier: Verifier,
) -> Result<Handle> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(state_dir)
        .map_err(|e| Error::Generic(format!("{}: {e}", state_dir.display())))?;
    let state_dir = state_dir.to_path_buf();
    let (sender, receiver) = mpsc::channel::<Job>();
    let (ready_tx, ready_rx) = mpsc::channel::<Result<()>>();
    let thread = std::thread::Builder::new()
        .name("authenticator".into())
        .spawn(move || {
            let tpm = match Tpm::open(&tcti) {
                Ok(tpm) => {
                    let _ = ready_tx.send(Ok(()));
                    tpm
                }
                Err(err) => {
                    let _ = ready_tx.send(Err(err));
                    return;
                }
            };
            let mut authenticator = Authenticator::new(tpm, state_dir, users, verifier);
            while let Ok(job) = receiver.recv() {
                match job {
                    Job::Ctap(request) => {
                        let ctx = RequestContext {
                            cancel: &request.cancel,
                            status: &request.status,
                        };
                        let response = authenticator.handle(&request.payload, &ctx);
                        let _ = request.reply.send(response);
                    }
                    Job::Manage(request) => authenticator.manage(request),
                }
            }
        })?;
    ready_rx
        .recv()
        .map_err(|_| Error::Generic("authenticator thread failed to start".into()))??;
    Ok(Handle {
        sender: Some(Jobs(sender)),
        thread: Some(thread),
    })
}
