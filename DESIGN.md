# Design

## Components

- `gkey-service` runs as the logged in user, normally as a systemd
  user service.  It creates a virtual USB HID device through UHID that
  web browsers recognise as a FIDO2 security key, and implements the
  CTAPHID transport and the CTAP 2.0 commands on it.
- `gkey` is a command line tool to list and delete credentials and to
  describe the TPM and the keystore.
- A GTK4 key management tool is planned.

The CTAPHID engine (`src/ctaphid.rs`) runs on an asynchronous event
loop.  CBOR requests are handed to the authenticator (`src/ctap2.rs`),
which owns the TPM connection and runs on its own thread, so that
keepalive messages and cancellation keep working while the
authenticator waits for the TPM or for the user.

## Root of trust

All keys descend from a storage primary key (ECC P-256, restricted
decryption) that the TPM derives from the seed of its owner hierarchy
each time gkey connects.  Nothing is stored in TPM non-volatile memory.

- Each credential is a P-256 signing key created by `TPM2_Create` under
  the primary key, with `fixedTPM` and `fixedParent`.  Its wrapped
  private area is stored in the keystore and loaded only to sign.
- The keystore is encrypted with AES-256-GCM.  Its key comes from the
  TPM's random number generator and is sealed to the TPM as a keyed
  hash object.
- Commands run in an HMAC session salted with the primary key, with
  command and response parameter encryption.
- The keystore records a digest of the primary public key, to report
  a cleared or different TPM clearly.

## Keystore

A single CBOR file in `$XDG_DATA_HOME/gkey/keystore` holds the sealed
key and the encrypted credential list.  It is replaced atomically on
every change, and access is serialised with `flock` on
`keystore.lock`, so `gkey` and `gkey-service` can run at the same time.

Credential IDs are 16 random bytes.  Every credential, discoverable or
not, is kept in the keystore, so credentials can be listed and deleted.

## User consent

User presence is a pinentry confirmation dialog.  User verification
runs PAM (service `gkey`) for the user running the service, relaying
PAM prompts through pinentry, so that passwords, fingerprint readers
and other PAM modules can be used.  Alternatively an external command
decides.

## Future work

- PCR policies binding keys to the boot state
- clientPIN and pinUvAuthToken (CTAP 2.1)
- the hmac-secret and credProtect extensions
- the GTK4 management tool
