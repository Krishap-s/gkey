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

//! End to end tests of the authenticator against a TPM.
//!
//! These tests need a TPM they are allowed to use, normally a software
//! TPM started by `make check`.  Set GKEY_TEST_TCTI to its TCTI, for
//! instance `swtpm:host=127.0.0.1,port=2321`; otherwise the tests are
//! skipped.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8};
use std::sync::Mutex;

use ciborium::Value;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use gkey::ctap2::{self, Authenticator, RequestContext};
use gkey::keystore::Keystore;
use gkey::tpm::Tpm;
use gkey::verify::{Method, Verifier};

/// Software TPMs serve one connection at a time.
static TPM_LOCK: Mutex<()> = Mutex::new(());

fn tcti() -> Option<String> {
    match std::env::var("GKEY_TEST_TCTI") {
        Ok(tcti) if !tcti.is_empty() => Some(tcti),
        _ => {
            eprintln!("GKEY_TEST_TCTI is not set; skipping TPM test");
            None
        }
    }
}

fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gkey-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn int(v: i64) -> Value {
    Value::Integer(v.into())
}

fn text(v: &str) -> Value {
    Value::Text(v.into())
}

fn get(map: &Value, key: i64) -> &Value {
    match map {
        Value::Map(m) => m
            .iter()
            .find(|(k, _)| *k == int(key))
            .map(|(_, v)| v)
            .unwrap_or_else(|| panic!("missing key {key}")),
        _ => panic!("not a map"),
    }
}

fn get_text<'a>(map: &'a Value, key: &str) -> Option<&'a Value> {
    match map {
        Value::Map(m) => m.iter().find(|(k, _)| *k == text(key)).map(|(_, v)| v),
        _ => panic!("not a map"),
    }
}

fn bytes(value: &Value) -> &[u8] {
    match value {
        Value::Bytes(b) => b,
        _ => panic!("not bytes"),
    }
}

struct Harness {
    authenticator: Authenticator,
}

impl Harness {
    fn call(&mut self, command: u8, parameters: Option<Value>) -> Result<Value, u8> {
        let mut request = vec![command];
        if let Some(parameters) = parameters {
            ciborium::into_writer(&parameters, &mut request).unwrap();
        }
        let cancel = AtomicBool::new(false);
        let status = AtomicU8::new(0);
        let ctx = RequestContext {
            cancel: &cancel,
            status: &status,
        };
        let response = self.authenticator.handle(&request, &ctx);
        match response.split_first() {
            Some((0, [])) => Ok(Value::Null),
            Some((0, body)) => Ok(ciborium::from_reader(body).unwrap()),
            Some((status, _)) => Err(*status),
            None => panic!("empty response"),
        }
    }

    fn make_credential(
        &mut self,
        rp: &str,
        user: &[u8],
        rk: bool,
        exclude: &[Vec<u8>],
    ) -> Result<(Vec<u8>, VerifyingKey), u8> {
        let mut parameters = vec![
            (int(1), Value::Bytes(vec![7; 32])),
            (
                int(2),
                Value::Map(vec![
                    (text("id"), text(rp)),
                    (text("name"), text("Example")),
                ]),
            ),
            (
                int(3),
                Value::Map(vec![
                    (text("id"), Value::Bytes(user.to_vec())),
                    (text("name"), text("alice@example.org")),
                    (text("displayName"), text("Alice")),
                ]),
            ),
            (
                int(4),
                Value::Array(vec![
                    Value::Map(vec![
                        (text("alg"), int(-8)),
                        (text("type"), text("public-key")),
                    ]),
                    Value::Map(vec![
                        (text("alg"), int(-7)),
                        (text("type"), text("public-key")),
                    ]),
                ]),
            ),
        ];
        if !exclude.is_empty() {
            parameters.push((
                int(5),
                Value::Array(
                    exclude
                        .iter()
                        .map(|id| {
                            Value::Map(vec![
                                (text("id"), Value::Bytes(id.clone())),
                                (text("type"), text("public-key")),
                            ])
                        })
                        .collect(),
                ),
            ));
        }
        parameters.push((
            int(7),
            Value::Map(vec![
                (text("rk"), Value::Bool(rk)),
                (text("uv"), Value::Bool(true)),
            ]),
        ));
        let response = self.call(ctap2::CMD_MAKE_CREDENTIAL, Some(Value::Map(parameters)))?;
        assert_eq!(*get(&response, 1), text("none"));
        let auth_data = bytes(get(&response, 2));
        assert_eq!(auth_data[..32], Sha256::digest(rp.as_bytes())[..]);
        assert_eq!(auth_data[32], 0x45, "flags UP | UV | AT");
        assert_eq!(&auth_data[37..53], &ctap2::AAGUID);
        let id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
        let id = auth_data[55..55 + id_len].to_vec();
        let cose: Value = ciborium::from_reader(&auth_data[55 + id_len..]).unwrap();
        assert_eq!(*get(&cose, 1), int(2));
        assert_eq!(*get(&cose, 3), int(-7));
        let mut point = vec![4u8];
        point.extend_from_slice(bytes(get(&cose, -2)));
        point.extend_from_slice(bytes(get(&cose, -3)));
        let key = VerifyingKey::from_sec1_bytes(&point).expect("valid P-256 point");
        Ok((id, key))
    }

    fn get_assertion(&mut self, rp: &str, allow: &[Vec<u8>], uv: bool) -> Result<Value, u8> {
        let mut parameters = vec![(int(1), text(rp)), (int(2), Value::Bytes(vec![9; 32]))];
        if !allow.is_empty() {
            parameters.push((
                int(3),
                Value::Array(
                    allow
                        .iter()
                        .map(|id| {
                            Value::Map(vec![
                                (text("id"), Value::Bytes(id.clone())),
                                (text("type"), text("public-key")),
                            ])
                        })
                        .collect(),
                ),
            ));
        }
        parameters.push((int(5), Value::Map(vec![(text("uv"), Value::Bool(uv))])));
        self.call(ctap2::CMD_GET_ASSERTION, Some(Value::Map(parameters)))
    }
}

fn check_assertion(response: &Value, key: &VerifyingKey, count: u32) {
    let auth_data = bytes(get(response, 2));
    assert_eq!(auth_data.len(), 37);
    assert_eq!(
        u32::from_be_bytes(auth_data[33..37].try_into().unwrap()),
        count
    );
    let mut message = auth_data.to_vec();
    message.extend_from_slice(&[9; 32]);
    let signature = Signature::from_der(bytes(get(response, 3))).expect("DER signature");
    key.verify(&message, &signature)
        .expect("signature verifies");
}

#[test]
fn register_and_authenticate() {
    let Some(tcti) = tcti() else { return };
    let _guard = TPM_LOCK.lock().unwrap();
    let dir = scratch_dir("flow");
    let tpm = Tpm::open(&tcti).unwrap();
    let mut h = Harness {
        authenticator: Authenticator::new(
            tpm,
            dir.clone(),
            Verifier {
                method: Method::Command("true".into()),
            },
        ),
    };

    let info = h.call(ctap2::CMD_GET_INFO, None).unwrap();
    assert_eq!(bytes(get(&info, 3)), &ctap2::AAGUID);

    // Two discoverable credentials and a server-side one.
    let (alice, alice_key) = h
        .make_credential("example.org", b"alice", true, &[])
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let (bob, bob_key) = h.make_credential("example.org", b"bob", true, &[]).unwrap();
    let (server, server_key) = h
        .make_credential("other.org", b"carol", false, &[])
        .unwrap();
    assert_ne!(alice, bob);

    // Excluded credentials are refused.
    assert_eq!(
        h.make_credential("example.org", b"alice", true, std::slice::from_ref(&alice))
            .err(),
        Some(ctap2::CTAP2_ERR_CREDENTIAL_EXCLUDED)
    );

    // Discoverable sign in returns the newest credential first.
    let first = h.get_assertion("example.org", &[], true).unwrap();
    assert_eq!(*get(&first, 5), int(2));
    assert_eq!(get_text(get(&first, 1), "id").map(bytes), Some(&bob[..]));
    assert_eq!(
        get_text(get(&first, 4), "name"),
        Some(&text("alice@example.org"))
    );
    check_assertion(&first, &bob_key, 1);
    let next = h.call(ctap2::CMD_GET_NEXT_ASSERTION, None).unwrap();
    assert_eq!(get_text(get(&next, 1), "id").map(bytes), Some(&alice[..]));
    check_assertion(&next, &alice_key, 1);
    assert_eq!(
        h.call(ctap2::CMD_GET_NEXT_ASSERTION, None).err(),
        Some(ctap2::CTAP2_ERR_NOT_ALLOWED)
    );

    // Server-side credentials need an allow list, and are bound to
    // their relying party.
    assert_eq!(
        h.get_assertion("other.org", &[], false).err(),
        Some(ctap2::CTAP2_ERR_NO_CREDENTIALS)
    );
    assert_eq!(
        h.get_assertion("example.org", std::slice::from_ref(&server), false)
            .err(),
        Some(ctap2::CTAP2_ERR_NO_CREDENTIALS)
    );
    let assertion = h
        .get_assertion("other.org", std::slice::from_ref(&server), false)
        .unwrap();
    check_assertion(&assertion, &server_key, 1);
    let assertion = h
        .get_assertion("other.org", std::slice::from_ref(&server), false)
        .unwrap();
    check_assertion(&assertion, &server_key, 2);

    // Everything survives reopening the keystore.
    drop(h);
    let mut tpm = Tpm::open(&tcti).unwrap();
    let store = Keystore::open(&dir, &mut tpm).unwrap();
    assert_eq!(store.credentials.len(), 3);
    drop(store);

    // A user who refuses consent gets nothing.
    let mut h = Harness {
        authenticator: Authenticator::new(
            tpm,
            dir.clone(),
            Verifier {
                method: Method::Command("false".into()),
            },
        ),
    };
    assert_eq!(
        h.get_assertion("example.org", &[], true).err(),
        Some(ctap2::CTAP2_ERR_OPERATION_DENIED)
    );
    assert_eq!(
        h.call(ctap2::CMD_RESET, None).err(),
        Some(ctap2::CTAP2_ERR_OPERATION_DENIED)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tampered_keystore_is_rejected() {
    let Some(tcti) = tcti() else { return };
    let _guard = TPM_LOCK.lock().unwrap();
    let dir = scratch_dir("tamper");
    let mut tpm = Tpm::open(&tcti).unwrap();
    drop(Keystore::create(&dir, &mut tpm).unwrap());
    let path = dir.join("keystore");
    let mut raw = std::fs::read(&path).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 1;
    std::fs::write(&path, raw).unwrap();
    let err = Keystore::open(&dir, &mut tpm)
        .err()
        .expect("tampering detected");
    assert!(err.to_string().contains("integrity"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}
