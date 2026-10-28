# gkey

gkey is a FIDO2 passkey authenticator for GNU/Linux whose root of trust
is the Trusted Platform Module (TPM).  It appears to web browsers as a
USB security key, so it works wherever security keys do, while the
private keys of your passkeys are generated and used inside the TPM
and never leave it.

- `gkey-service` is a system service that creates a virtual FIDO2
  security key through the kernel's UHID driver, implements CTAP 2.0
  over CTAPHID, and serves the user of the active session.
- `gkey` lets each user list, inspect and delete their own passkeys,
  through the service's D-Bus interface.

Only the service's own account may use the TPM.  Each user has a TPM
storage key protected by a random password that only the service can
read; their credential keys, ECC P-256 keys created by the TPM, and the
key encrypting their credential list are created under it, so no other
user or program can use them.  Every operation is confirmed through the
desktop's polkit authentication dialog.

## Building

You need Rust 1.80 or later (cargo and rustc), pkg-config and the TPM2
Software Stack (`tpm2-tss`) development files.  Then:

```sh
autoconf
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
make
make check
sudo make install
```

`make check` uses a temporary software TPM when `swtpm` is installed,
and python-fido2 1.x, when installed, as an independent FIDO2 client and
relying party.  See the file `INSTALL` for details.

## Setting up

```sh
sudo systemd-sysusers                 # creates the 'gkey' account
sudo modprobe uhid
sudo udevadm control --reload && sudo udevadm trigger /dev/uhid
sudo systemctl daemon-reload
sudo systemctl enable --now gkey.service
gkey list
```

Users need a polkit authentication agent in their desktop session, as
most desktops provide.  Do not add users to the `gkey` or `tss` groups.

The manual (`info gkey`, or `doc/gkey.texi`) explains the setup, the
security model and the options of both programs.

## Licence

gkey is free software, released under the GNU General Public License,
version 3 or later.  See the file `COPYING`.

Report bugs at <https://github.com/Krishap-s/gkey/issues>.
