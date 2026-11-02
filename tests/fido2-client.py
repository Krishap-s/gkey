#!/usr/bin/env python3
# Copyright (C) 2026 Krishap <krishapbusiness@gmail.com>
#
# This file is part of gkey.
#
# gkey is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Register and authenticate with gkey using the python-fido2 client
and server implementations, talking CTAPHID over the Unix socket of
tests/helpers/socket-authenticator.rs.  Then replay what OpenSSH asks of
a security key for "ssh-keygen -t ecdsa-sk" and ssh.

Usage: fido2-client.py SOCKET
"""

import hashlib
import os
import socket
import sys

from fido2.attestation import Attestation
from fido2.client import Fido2Client, UserInteraction
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.base import AuthenticatorData
from fido2.hid import CtapHidDevice
from fido2.hid.base import CtapHidConnection, HidDescriptor
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestationObject,
    PublicKeyCredentialCreationOptions,
    CollectedClientData,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)


class SocketConnection(CtapHidConnection):
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)

    def read_packet(self):
        data = b""
        while len(data) < 64:
            chunk = self.sock.recv(64 - len(data))
            if not chunk:
                raise OSError("connection closed")
            data += chunk
        return data

    def write_packet(self, data):
        self.sock.sendall(data.ljust(64, b"\0"))

    def close(self):
        self.sock.close()


class Interaction(UserInteraction):
    def request_uv(self, permissions, rd_id):
        return True


UP = AuthenticatorData.FLAG.UP
UV = AuthenticatorData.FLAG.UV
AT = AuthenticatorData.FLAG.AT
ED = AuthenticatorData.FLAG.ED
SSH = "ssh:"


def ok(name):
    print("ok:", name)


def ssh_enroll(device, resident=False, protect=None):
    """What OpenSSH's sk_enroll asks for, and what libfido2 checks in
    the answer (fido_cred_verify_self).  Returns the credential ID and
    public key."""
    ctap2 = Ctap2(device)
    challenge_hash = hashlib.sha256(b"ssh challenge").digest()
    response = ctap2.make_credential(
        challenge_hash,
        {"id": SSH},
        {"id": os.urandom(32), "name": "openssh", "displayName": "openssh"},
        [{"type": "public-key", "alg": -7}],
        extensions={"credProtect": protect} if protect else None,
        options={"rk": True} if resident else None,
    )
    auth_data = response.auth_data
    # Without a certificate, a self attestation signature is required:
    # the credential key signs the authenticator data and the hash.
    assert response.fmt == "packed", response.fmt
    assert "x5c" not in response.att_stmt and response.att_stmt["sig"]
    assert response.att_stmt["alg"] == -7
    Attestation.for_type("packed")().verify(response.att_stmt, auth_data, challenge_hash)
    assert auth_data.rp_id_hash == hashlib.sha256(SSH.encode()).digest()
    assert auth_data.flags & UP and auth_data.flags & AT
    # The extension output must be exactly what was asked for.
    if protect:
        assert auth_data.flags & ED
        assert dict(auth_data.extensions) == {"credProtect": protect}, auth_data.extensions
    else:
        assert not auth_data.flags & ED and not auth_data.extensions
    credential = auth_data.credential_data
    return credential.credential_id, credential.public_key


def ssh_sign(device, handle, public_key, up=True, uv=False):
    """What OpenSSH's sk_sign asks for, checked as libfido2 and sshd
    would.  Returns the flags of the authenticator data."""
    ctap2 = Ctap2(device)
    data_hash = hashlib.sha256(b"ssh signature data").digest()
    options = {"up": up}
    if uv:
        options["uv"] = True
    response = ctap2.get_assertion(
        SSH,
        data_hash,
        [{"type": "public-key", "id": handle}],
        options=options,
    )
    response.verify(data_hash, public_key)
    assert response.auth_data.rp_id_hash == hashlib.sha256(SSH.encode()).digest()
    return int(response.auth_data.flags)


def expect_error(code, function, *arguments, **options):
    try:
        function(*arguments, **options)
    except CtapError as error:
        assert error.code == code, error
        return
    raise AssertionError("expected %s" % code)


def check_openssh(device):
    info = Ctap2(device).info
    assert "credProtect" in info.extensions, info.extensions
    ok("credProtect is advertised")
    assert info.options["uv"], info.options
    ok("built-in user verification is advertised")

    # ssh-keygen -t ecdsa-sk
    handle, key = ssh_enroll(device)
    ok("enroll a plain key (self attestation verifies)")
    # ssh, touch required (the default)
    flags = ssh_sign(device, handle, key)
    assert flags & UP and not flags & UV, flags
    ok("sign with user presence")
    # ssh with no-touch-required keys, and the probe sent before every
    # signature to find the device holding the key handle
    assert ssh_sign(device, handle, key, up=False) == 0
    ok("sign without user presence (no flags)")
    flags = ssh_sign(device, handle, key, uv=True)
    assert flags & UP and flags & UV, flags
    ok("sign with user verification")

    # ssh-keygen -t ecdsa-sk -O resident
    resident, resident_key = ssh_enroll(device, resident=True, protect=2)
    ok("enroll a resident key (credProtect level 2)")
    ssh_sign(device, resident, resident_key)
    ok("sign with it by its key handle")

    # ssh-keygen -t ecdsa-sk -O verify-required
    required, required_key = ssh_enroll(device, protect=3)
    ok("enroll a verify-required key (credProtect level 3)")
    ssh_sign(device, required, required_key, uv=True)
    ok("sign with user verification")
    expect_error(
        CtapError.ERR.NO_CREDENTIALS, ssh_sign, device, required, required_key
    )
    ok("refused without user verification")

    # ssh-keygen: is there already a resident key for this application?
    expect_error(
        CtapError.ERR.NO_CREDENTIALS,
        Ctap2(device).get_assertion,
        SSH,
        bytes(32),
        options={"up": False},
    )
    ok("silent resident key lookup hides protected keys")


def main():
    descriptor = HidDescriptor(sys.argv[1], 0, 0, 64, 64, "gkey", None)
    device = CtapHidDevice(descriptor, SocketConnection(sys.argv[1]))
    info = device.call(0x10, b"\x04")
    assert info[0] == 0, info

    origin = "https://example.org"
    rp = PublicKeyCredentialRpEntity(id="example.org", name="Example")
    server = Fido2Server(rp)
    client = Fido2Client(device, origin, user_interaction=Interaction())

    user = PublicKeyCredentialUserEntity(
        id=b"user-1", name="alice", display_name="Alice"
    )
    options, state = server.register_begin(
        user,
        resident_key_requirement=ResidentKeyRequirement.REQUIRED,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    # python-fido2's high level client requires clientPIN support from
    # authenticators with built-in user verification, so register
    # through the CTAP2 layer and build the client data by hand.
    public_key = PublicKeyCredentialCreationOptions.from_dict(options["publicKey"])
    client_data = CollectedClientData.create(
        type=CollectedClientData.TYPE.CREATE,
        challenge=public_key.challenge,
        origin=origin,
    )
    ctap2 = Ctap2(device)
    assert ctap2.info.options["uv"] and ctap2.info.options["rk"]
    response = ctap2.make_credential(
        client_data.hash,
        {"id": rp.id, "name": rp.name},
        {"id": user.id, "name": user.name, "displayName": user.display_name},
        [{"type": "public-key", "alg": p.alg} for p in public_key.pub_key_cred_params],
        options={"rk": True, "uv": True},
    )
    attestation = AttestationObject.create(response.fmt, response.auth_data, response.att_stmt)
    auth_data = server.register_complete(state, client_data, attestation)
    assert auth_data.is_user_verified()
    credential = auth_data.credential_data
    print("registered", credential.credential_id.hex())

    # Discoverable login: no allow list.
    options, state = server.authenticate_begin(
        user_verification=UserVerificationRequirement.DISCOURAGED
    )
    selection = client.get_assertion(options["publicKey"])
    assertion = selection.get_response(0)
    server.authenticate_complete(
        state,
        [credential],
        assertion.credential_id,
        assertion.client_data,
        assertion.authenticator_data,
        assertion.signature,
    )
    assert assertion.user_handle == b"user-1", assertion.user_handle
    print("authenticated with discoverable credential")

    # Login with an allow list.
    options, state = server.authenticate_begin([credential])
    selection = client.get_assertion(options["publicKey"])
    assertion = selection.get_response(0)
    server.authenticate_complete(
        state,
        [credential],
        assertion.credential_id,
        assertion.client_data,
        assertion.authenticator_data,
        assertion.signature,
    )
    assert assertion.authenticator_data.counter == 2
    print("authenticated with allow list")

    check_openssh(device)
    print("all OpenSSH style checks passed")


if __name__ == "__main__":
    main()
