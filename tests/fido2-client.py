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
examples/socket-authenticator.rs.

Usage: fido2-client.py SOCKET
"""

import socket
import sys

from fido2.client import Fido2Client, UserInteraction
from fido2.ctap2 import Ctap2
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


if __name__ == "__main__":
    main()
