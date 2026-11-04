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
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ciborium::Value;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};

use crate::ctaphid::{Request, STATUS_PROCESSING, STATUS_UPNEEDED};
use crate::keystore::{Credential, Keystore};
use crate::prelude::*;
use crate::prompt;
use crate::tpm::Tpm;
use crate::verify::{Kind, Operation, Outcome, Verifier};

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
/// The authenticator data carries extension outputs.
const FLAG_ED: u8 = 0x80;

/// credProtect levels (CTAP 2.1, section 12.1): the credential may be
/// used without user verification (1), or found without user
/// verification only when its ID is given (2), or never (3).
const CRED_PROTECT_OPTIONAL: u8 = 1;
const CRED_PROTECT_WITH_LIST: u8 = 2;
const CRED_PROTECT_REQUIRED: u8 = 3;
const CREDENTIAL_ID_SIZE: usize = 16;
const MAX_MESSAGE_SIZE: i64 = crate::ctaphid::MAX_MESSAGE_SIZE as i64;
/// How long the platform has to fetch the remaining assertions.
const NEXT_ASSERTION_TIMEOUT: Duration = Duration::from_secs(30);

type CtapResult<T> = std::result::Result<T, u8>;

/// The name of a CTAP2 command, for logs.
pub fn command_name(command: u8) -> &'static str {
    match command {
        CMD_MAKE_CREDENTIAL => "makeCredential",
        CMD_GET_ASSERTION => "getAssertion",
        CMD_GET_INFO => "getInfo",
        CMD_CLIENT_PIN => "clientPIN",
        CMD_RESET => "reset",
        CMD_GET_NEXT_ASSERTION => "getNextAssertion",
        _ => "unknown command",
    }
}

/// The name of a CTAP status, for logs.
pub fn status_name(status: u8) -> &'static str {
    match status {
        CTAP2_OK => "success",
        CTAP1_ERR_INVALID_COMMAND => "invalid command",
        CTAP1_ERR_INVALID_PARAMETER => "invalid parameter",
        CTAP2_ERR_CBOR_UNEXPECTED_TYPE => "unexpected CBOR type",
        CTAP2_ERR_INVALID_CBOR => "invalid CBOR",
        CTAP2_ERR_MISSING_PARAMETER => "missing parameter",
        CTAP2_ERR_CREDENTIAL_EXCLUDED => "credential excluded",
        CTAP2_ERR_UNSUPPORTED_ALGORITHM => "unsupported algorithm",
        CTAP2_ERR_OPERATION_DENIED => "operation denied",
        CTAP2_ERR_INVALID_OPTION => "invalid option",
        CTAP2_ERR_KEEPALIVE_CANCEL => "cancelled",
        CTAP2_ERR_NO_CREDENTIALS => "no credentials",
        CTAP2_ERR_NOT_ALLOWED => "not allowed",
        CTAP2_ERR_PIN_AUTH_INVALID => "PIN authentication invalid",
        CTAP2_ERR_PIN_NOT_SET => "PIN not set",
        CTAP2_ERR_OTHER => "internal error",
        _ => "other error",
    }
}

/// How noteworthy a refused request is: routine ones (a client looking
/// for a credential that is not here, the platform asking the user to
/// pick a security key) only show when debugging, the user's own
/// decisions are informational, and everything that points at a
/// problem with the client or with gkey is a warning.
fn status_level(status: u8) -> log::Level {
    match status {
        CTAP2_ERR_NO_CREDENTIALS | CTAP2_ERR_PIN_NOT_SET => log::Level::Debug,
        CTAP2_ERR_OPERATION_DENIED
        | CTAP2_ERR_KEEPALIVE_CANCEL
        | CTAP2_ERR_CREDENTIAL_EXCLUDED
        | CTAP2_ERR_NOT_ALLOWED => log::Level::Info,
        _ => log::Level::Warn,
    }
}

/// The name of a COSE algorithm, for logs.
fn algorithm_name(alg: i128) -> String {
    match alg {
        -7 => "ES256".into(),
        -8 => "EdDSA".into(),
        -35 => "ES384".into(),
        -36 => "ES512".into(),
        -37 => "PS256".into(),
        -257 => "RS256".into(),
        other => other.to_string(),
    }
}

/// A relying party ID made safe to put in a log line: it comes from a
/// web page, and control characters could fake further lines.  It is
/// quoted because it may itself end in punctuation ("ssh:").
fn shown(rp_id: &str) -> String {
    format!("'{}'", prompt::display_host(rp_id, 64))
}

/// What the user is asked to allow, as a phrase for logs.
fn describe(operation: Operation, rp_id: Option<&str>) -> String {
    match (operation, rp_id) {
        (Operation::Create, Some(rp)) => format!("create a passkey for {}", shown(rp)),
        (Operation::Create, None) => "create a passkey".into(),
        (Operation::SignIn, Some(rp)) => format!("sign in to {}", shown(rp)),
        (Operation::SignIn, None) => "use gkey as the security key".into(),
        (Operation::Reset, _) => "delete all passkeys".into(),
    }
}

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

/// Whether the credProtect level of `credential` lets a request find
/// it: `listed` says the request names its ID, `verified` that the user
/// was verified.  Without being found, the credential does not exist
/// as far as the client can tell.
fn visible(credential: &Credential, verified: bool, listed: bool) -> bool {
    match credential.cred_protect {
        CRED_PROTECT_REQUIRED => verified,
        CRED_PROTECT_WITH_LIST => verified || listed,
        _ => true,
    }
}

/// The credProtect level asked for in the extensions map of a
/// makeCredential request, if any.  Other extensions are ignored.
fn cred_protect(extensions: Option<&Value>) -> CtapResult<Option<u8>> {
    let Some(extensions) = extensions else {
        return Ok(None);
    };
    match get_text(as_map(extensions)?, "credProtect") {
        None => Ok(None),
        Some(Value::Integer(level)) => match u8::try_from(i128::from(*level)) {
            Ok(
                level @ (CRED_PROTECT_OPTIONAL | CRED_PROTECT_WITH_LIST | CRED_PROTECT_REQUIRED),
            ) => Ok(Some(level)),
            _ => {
                log::warn!(
                    "makeCredential: the credProtect level {} is not 1, 2 or 3",
                    i128::from(*level)
                );
                Err(CTAP2_ERR_INVALID_OPTION)
            }
        },
        Some(_) => Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
    }
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
    keystore: PathBuf,
    verifier: Verifier,
    pending: Option<PendingAssertions>,
}

impl Authenticator {
    pub fn new(tpm: Tpm, keystore: PathBuf, verifier: Verifier) -> Self {
        Authenticator {
            tpm,
            keystore,
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
        log::debug!("{} request", command_name(command));
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
                log::log!(
                    status_level(status),
                    "{} refused: {} ({status:#04x})",
                    command_name(command),
                    status_name(status)
                );
                vec![status]
            }
        }
    }

    /// Ask the user to allow `operation` on `rp_id` (when it concerns
    /// a site).
    fn consent(
        &self,
        kind: Kind,
        operation: Operation,
        rp_id: Option<&str>,
        description: &str,
        ctx: &RequestContext,
    ) -> CtapResult<()> {
        let what = describe(operation, rp_id);
        let asked = match kind {
            Kind::Presence => "user presence",
            Kind::Verification => "user verification",
        };
        log::info!("asking for {asked} to {what}");
        ctx.status.store(STATUS_UPNEEDED, Ordering::Relaxed);
        let outcome = self.verifier.ask(kind, operation, description, ctx.cancel);
        ctx.status.store(STATUS_PROCESSING, Ordering::Relaxed);
        match outcome {
            Ok(Outcome::Granted) => {
                log::info!("the user allowed it to {what}");
                Ok(())
            }
            Ok(Outcome::Denied) => {
                log::info!("the user did not allow it to {what}");
                Err(CTAP2_ERR_OPERATION_DENIED)
            }
            Ok(Outcome::Cancelled) => {
                log::info!("the request to {what} was cancelled");
                Err(CTAP2_ERR_KEEPALIVE_CANCEL)
            }
            Err(err) => {
                log::error!("cannot obtain user consent to {what}: {err}");
                Err(CTAP2_ERR_OPERATION_DENIED)
            }
        }
    }

    fn open_keystore(&mut self) -> CtapResult<Keystore> {
        Keystore::open_or_create(&self.keystore, &mut self.tpm).map_err(internal)
    }

    /// Handle the zero length pinAuth that platforms send to make the
    /// user pick an authenticator (CTAP 2.0, section 5.1, step 2).
    fn pin_auth(&self, value: Option<&Value>, ctx: &RequestContext) -> CtapResult<()> {
        match value {
            None => Ok(()),
            Some(value) if as_bytes(value)?.is_empty() => {
                self.consent(
                    Kind::Presence,
                    Operation::SignIn,
                    None,
                    &prompt::choose_key(),
                    ctx,
                )?;
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
        let client_data_hash = client_data_hash(get_int(parameters, 1))?;
        let rp = as_map(get_int(parameters, 2).ok_or(CTAP2_ERR_MISSING_PARAMETER)?)?;
        let user = as_map(get_int(parameters, 3).ok_or(CTAP2_ERR_MISSING_PARAMETER)?)?;
        let algorithms = as_array(get_int(parameters, 4).ok_or(CTAP2_ERR_MISSING_PARAMETER)?)?;
        let exclude = get_int(parameters, 5).map(credential_ids).transpose()?;
        let options = options(get_int(parameters, 7))?;
        let cred_protect = cred_protect(get_int(parameters, 6))?;
        self.pin_auth(get_int(parameters, 8), ctx)?;

        let rp_id = as_text(get_text(rp, "id").ok_or(CTAP2_ERR_MISSING_PARAMETER)?)?.to_string();
        let rp_name = optional_text(rp, "name")?;
        let user_id = as_bytes(get_text(user, "id").ok_or(CTAP2_ERR_MISSING_PARAMETER)?)?.to_vec();
        let user_name = optional_text(user, "name")?;
        let user_display_name = optional_text(user, "displayName")?;

        log::debug!(
            "makeCredential for {}: resident key {}, user verification {}",
            shown(&rp_id),
            options.rk,
            options.uv
        );
        let mut supported = false;
        let mut offered = Vec::new();
        for algorithm in algorithms {
            let algorithm = as_map(algorithm)?;
            let kind = as_text(get_text(algorithm, "type").ok_or(CTAP2_ERR_MISSING_PARAMETER)?)?;
            let alg = match get_text(algorithm, "alg").ok_or(CTAP2_ERR_MISSING_PARAMETER)? {
                Value::Integer(i) => i128::from(*i),
                _ => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            };
            offered.push(algorithm_name(alg));
            if kind == "public-key" && alg == COSE_ES256 as i128 {
                supported = true;
            }
        }
        if !supported {
            log::warn!(
                "makeCredential for {} refused: the client offers only {}, and gkey supports \
                 only ES256 (ECDSA P-256), since TPMs have no Ed25519; for OpenSSH use \
                 'ssh-keygen -t ecdsa-sk'",
                shown(&rp_id),
                offered.join(", ")
            );
            return Err(CTAP2_ERR_UNSUPPORTED_ALGORITHM);
        }
        if !options.up {
            log::warn!(
                "makeCredential for {} refused: the client sent up=false",
                shown(&rp_id)
            );
            return Err(CTAP2_ERR_INVALID_OPTION);
        }

        if let Some(exclude) = exclude {
            let keystore = self.open_keystore()?;
            let excluded = exclude.iter().any(|id| {
                keystore.find(id).is_some_and(|i| {
                    let c = &keystore.credentials[i];
                    c.rp_id == rp_id && visible(c, options.uv, true)
                })
            });
            drop(keystore);
            if excluded {
                log::info!(
                    "makeCredential for {}: a credential on the exclude list already exists",
                    shown(&rp_id)
                );
                self.consent(
                    Kind::Presence,
                    Operation::Create,
                    Some(&rp_id),
                    &prompt::already_registered(&rp_id),
                    ctx,
                )?;
                return Err(CTAP2_ERR_CREDENTIAL_EXCLUDED);
            }
        }

        let description = prompt::create(
            &rp_id,
            &prompt::account(user_name.as_deref().or(user_display_name.as_deref())),
        );
        let kind = if options.uv {
            Kind::Verification
        } else {
            Kind::Presence
        };
        self.consent(kind, Operation::Create, Some(&rp_id), &description, ctx)?;

        let key = self.tpm.create_signing_key().map_err(internal)?;
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
            cred_protect: cred_protect.unwrap_or(0),
        };

        let mut flags = FLAG_UP | FLAG_AT;
        if options.uv {
            flags |= FLAG_UV;
        }
        if cred_protect.is_some() {
            flags |= FLAG_ED;
        }
        let mut auth_data = Vec::with_capacity(256);
        auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        auth_data.push(flags);
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        auth_data.extend_from_slice(&AAGUID);
        auth_data.extend_from_slice(&(id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&id);
        auth_data.extend_from_slice(&cose_key(&public_key));
        if let Some(level) = cred_protect {
            // The extension output echoes the level that was applied.
            auth_data.extend_from_slice(&encode(&Value::Map(vec![(
                text("credProtect"),
                int(level.into()),
            )])));
        }

        // Self attestation (WebAuthn, "packed" format): the credential
        // key signs the authenticator data and the client data hash.
        // This proves possession of the key, and is all that clients
        // such as OpenSSH accept from an authenticator without an
        // attestation certificate.
        let mut hash = Sha256::new();
        hash.update(&auth_data);
        hash.update(client_data_hash);
        let digest: [u8; 32] = hash.finalize().into();
        let signature = self
            .tpm
            .sign(&credential.tpm_public, &credential.tpm_private, &digest)
            .map_err(internal)?;

        let mut keystore = self.open_keystore()?;
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
            "created credential {} for {} ({}{}{})",
            crate::keystore::hex(&id),
            shown(&rp_id),
            if options.rk {
                "resident key"
            } else {
                "key handle"
            },
            if options.uv {
                ", user verification"
            } else {
                ""
            },
            match cred_protect {
                Some(level) => format!(", credProtect {level}"),
                None => String::new(),
            }
        );

        Ok(Some(Value::Map(vec![
            (int(1), text("packed")),
            (int(2), Value::Bytes(auth_data)),
            (
                int(3),
                Value::Map(vec![
                    (text("alg"), int(COSE_ES256)),
                    (text("sig"), Value::Bytes(signature)),
                ]),
            ),
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
        self.pin_auth(get_int(parameters, 6), ctx)?;
        if options.rk {
            return Err(CTAP2_ERR_INVALID_OPTION);
        }

        log::debug!(
            "getAssertion for {}: presence {}, verification {}, {} credential(s) listed",
            shown(&rp_id),
            options.up,
            options.uv,
            allow.as_ref().map_or(0, Vec::len)
        );
        let keystore = self.open_keystore()?;
        let allow = allow.filter(|ids| !ids.is_empty());
        let mut matches: Vec<&Credential> = match &allow {
            Some(ids) => ids
                .iter()
                .filter_map(|id| keystore.find(id))
                .map(|i| &keystore.credentials[i])
                .filter(|c| c.rp_id == rp_id && visible(c, options.uv, true))
                .take(1)
                .collect(),
            None => keystore
                .credentials
                .iter()
                .filter(|c| c.discoverable && c.rp_id == rp_id && visible(c, options.uv, false))
                .collect(),
        };
        if matches.is_empty() {
            // Not an error worth a warning: clients look for
            // credentials that may not be here.
            let hidden = keystore
                .credentials
                .iter()
                .filter(|c| c.rp_id == rp_id)
                .filter(|c| match &allow {
                    Some(ids) => ids.iter().any(|id| id.as_slice() == c.id.as_slice()),
                    None => c.discoverable,
                })
                .filter(|c| !visible(c, options.uv, allow.is_some()))
                .count();
            log::debug!(
                "getAssertion for {}: no credential to offer{}",
                shown(&rp_id),
                if hidden > 0 {
                    format!(" ({hidden} hidden by credProtect without user verification)")
                } else {
                    String::new()
                }
            );
            return Err(CTAP2_ERR_NO_CREDENTIALS);
        }
        matches.sort_by_key(|c| std::cmp::Reverse(c.created));
        let pending_rp = rp_id.clone();
        let ids: VecDeque<Vec<u8>> = matches.iter().map(|c| c.id.to_vec()).collect();
        let account = match matches.as_slice() {
            [only] => prompt::account(
                only.user_name
                    .as_deref()
                    .or(only.user_display_name.as_deref()),
            ),
            many => prompt::accounts(many.len()),
        };
        let description = prompt::sign_in(&rp_id, &account);
        drop(keystore);

        let mut flags = 0;
        if options.uv {
            self.consent(
                Kind::Verification,
                Operation::SignIn,
                Some(&pending_rp),
                &description,
                ctx,
            )?;
            flags |= FLAG_UP | FLAG_UV;
        } else if options.up {
            self.consent(
                Kind::Presence,
                Operation::SignIn,
                Some(&pending_rp),
                &description,
                ctx,
            )?;
            flags |= FLAG_UP;
        } else {
            // What OpenSSH does before every signature, to find the
            // security key holding a key handle: no prompt, and the
            // signature carries no user presence flag.
            log::debug!(
                "getAssertion for {}: answering without user presence, as asked",
                shown(&rp_id)
            );
        }

        let mut pending = PendingAssertions {
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
        if pending.started.elapsed() > NEXT_ASSERTION_TIMEOUT {
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
        let mut keystore = self.open_keystore()?;
        let index = keystore.find(id).ok_or(CTAP2_ERR_NO_CREDENTIALS)?;
        let credential = &mut keystore.credentials[index];
        if credential.rp_id != pending.rp_id {
            return Err(CTAP2_ERR_NO_CREDENTIALS);
        }
        credential.sign_count = credential.sign_count.wrapping_add(1);
        let credential = credential.clone();
        keystore.save(&mut self.tpm).map_err(internal)?;
        drop(keystore);

        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&Sha256::digest(pending.rp_id.as_bytes()));
        auth_data.push(pending.flags);
        auth_data.extend_from_slice(&credential.sign_count.to_be_bytes());
        let mut hash = Sha256::new();
        hash.update(&auth_data);
        hash.update(pending.client_data_hash);
        let digest: [u8; 32] = hash.finalize().into();
        let signature = self
            .tpm
            .sign(&credential.tpm_public, &credential.tpm_private, &digest)
            .map_err(internal)?;
        // A silent assertion is what OpenSSH asks for before every
        // signature, to find the key; only the real ones are news.
        log::log!(
            if pending.flags & FLAG_UP != 0 {
                log::Level::Info
            } else {
                log::Level::Debug
            },
            "signed assertion for {} with credential {}{}",
            shown(&pending.rp_id),
            credential.id_hex(),
            if pending.flags & FLAG_UV != 0 {
                " (user verification)"
            } else if pending.flags & FLAG_UP != 0 {
                " (user presence)"
            } else {
                " (no user presence)"
            }
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
            // credProtect lets clients such as OpenSSH create resident
            // and verification-required keys.
            (int(2), Value::Array(vec![text("credProtect")])),
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
        self.consent(
            Kind::Verification,
            Operation::Reset,
            None,
            &prompt::reset(),
            ctx,
        )?;
        let mut keystore = self.open_keystore()?;
        keystore.credentials.clear();
        keystore.save(&mut self.tpm).map_err(internal)?;
        log::warn!("all credentials deleted by authenticatorReset");
        Ok(None)
    }
}

/// A running authenticator thread.
pub struct Handle {
    sender: Option<mpsc::Sender<Request>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Handle {
    /// A channel on which to submit requests.
    pub fn sender(&self) -> mpsc::Sender<Request> {
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

/// Start the authenticator on its own thread.  The TPM connection is
/// opened before this returns.  The keystore is only opened when
/// requests arrive, so that a set-user-ID caller can drop its privileges
/// first.
pub fn spawn(tcti: String, keystore: PathBuf, verifier: Verifier) -> Result<Handle> {
    let (sender, receiver) = mpsc::channel::<Request>();
    let (ready_tx, ready_rx) = mpsc::channel::<Result<()>>();
    let thread = std::thread::Builder::new()
        .name("authenticator".into())
        .spawn(move || {
            let tpm = match Tpm::open(&tcti) {
                Ok(mut tpm) => {
                    log::info!("connected to the TPM ({})", tpm.vendor());
                    let _ = ready_tx.send(Ok(()));
                    tpm
                }
                Err(err) => {
                    let _ = ready_tx.send(Err(err));
                    return;
                }
            };
            let mut authenticator = Authenticator::new(tpm, keystore, verifier);
            while let Ok(request) = receiver.recv() {
                let ctx = RequestContext {
                    cancel: &request.cancel,
                    status: &request.status,
                };
                let response = authenticator.handle(&request.payload, &ctx);
                let _ = request.reply.send(response);
            }
        })?;
    ready_rx
        .recv()
        .map_err(|_| Error::Generic("authenticator thread failed to start".into()))??;
    Ok(Handle {
        sender: Some(sender),
        thread: Some(thread),
    })
}
