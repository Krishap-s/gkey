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

## Privileges

Only the `gkey` account may use the TPM (an ACL on `/dev/tpmrm0`, set
by udev, which keeps the distribution's `tss` permissions) and
`/dev/uhid` (owned by it).  `gkey-service` and `gkey` are installed
`gkey:gkey`, mode 4755.  At startup they:

1. remove the environment variables that would redirect them (the
   TCTI variables, `TSS2_*`, `DBUS_SYSTEM_BUS_ADDRESS`) and refuse the
   options that would (`--tcti`, `--uhid`, `--verify=command`), since
   anyone may run them with any arguments;
2. open the TPM, for the service `/dev/uhid`, and connect to the
   system bus;
3. drop back to the user for good with `setresuid`, and check;
4. only then open the keystore, with the user's own permissions.

The bus records a client's identity when it connects, so polkit still
sees the connection as `gkey`, which the policy names as the owner of
gkey's actions (`org.freedesktop.policykit.owner`).  Only an owner (or
root) may pass details to polkit, so this is what lets the dialog show
the web site and account.  The subject of every check is the
program's own process, running as the user.

Programs running as the user, malware included, therefore cannot use
the TPM or create HID devices, and the kernel keeps them from
debugging the set-user-ID processes.  They can still delete or roll
back the keystore file, and send requests that each need the user's
password in the polkit dialog.  The code that runs as `gkey` before
the drop is kept short: a flaw there could let an attacker act as
`gkey`, which owns the installed programs.

## Keystore

A single CBOR file in `$XDG_DATA_HOME/gkey/keystore` holds the sealed
key and the encrypted credential list.  It is replaced atomically on
every change, and access is serialised with `flock` on
`keystore.lock`, so `gkey` and `gkey-service` can run at the same time.

Credential IDs are 16 random bytes.  Every credential, discoverable or
not, is kept in the keystore, so credentials can be listed and deleted.

## User consent

The service asks polkit to authorize one of three actions (create a
passkey, sign in, delete all passkeys) for its own process.  polkit
attributes a process of a user service to the user's graphical
session, whose authentication agent asks for the password and checks
it through PAM, so fingerprint readers and other PAM modules work and
the service never sees the password.  polkit has no confirmation
without authentication, so presence and verification both require it,
and only the actions' owner may pass details (messages are plain
text of a few short lines, see `src/prompt.rs`, because agents treat
markup differently and policy files can only hold one-line messages): running set-user-ID
`gkey`, the programs describe each request, including the web site,
in the dialog.  The `gkey` program asks for the `manage` action before
every command, and starts `pkttyagent` on a terminal.  Alternatively
an external command decides.

## OpenSSH

`ssh-keygen -t ecdsa-sk` works with the P-256 credentials gkey already
creates.  OpenSSH, through libfido2, needs three things beyond plain
WebAuthn:

- the attestation statement: with no certificate, libfido2 requires a
  self attestation signature (`fido_cred_verify_self`), so
  `makeCredential` returns the `packed` format signed by the new
  credential key (a second TPM signature per registration);
- the `credProtect` extension for resident and verify-required keys:
  it is advertised in `getInfo`, stored per credential, echoed in the
  authenticator data, and enforced (level 3 credentials do not exist
  without user verification, level 2 ones are hidden from discovery);
- silent assertions (`up=false`) to find the device holding a key
  handle before every signature, which therefore get no dialog.

`tests/helpers/libfido2-check.c` runs the calls of OpenSSH's `sk_enroll`
and `sk_sign` through libfido2 against the real authenticator.  Ed25519
is impossible without leaving the TPM: no TPM curve supports it.

## Future work

- PCR policies binding keys to the boot state
- clientPIN and pinUvAuthToken (CTAP 2.1)
- the hmac-secret and credProtect extensions
- the GTK4 management tool
