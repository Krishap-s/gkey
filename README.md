# gkey

gkey is a FIDO2 passkey authenticator for GNU/Linux whose root of trust
is the Trusted Platform Module (TPM).  It appears to web browsers as a
USB security key, so it works wherever security keys do, while the
private keys of your passkeys are generated and used inside the TPM
and never leave it.

- `gkey-service` creates a virtual FIDO2 security key through the
  kernel's UHID driver and implements CTAP 2.0 over CTAPHID.
- `gkey` lists, inspects and deletes the stored passkeys.

Each credential is an ECC P-256 key created by the TPM under a storage
primary key derived from the TPM's owner seed.  The credential list is
encrypted with AES-256-GCM under a key sealed to the TPM.  The user
authenticates for every operation in the desktop's polkit dialog.

Both programs are installed set-group-ID `gkey`, the only group allowed
to use the TPM and `/dev/uhid`.  They open those devices, then drop the
group for good, so programs running as you, malware included, can
neither use the TPM nor create HID devices.

## Building

You need Rust (cargo and rustc), a C compiler, pkg-config, the TPM2
Software Stack (`tpm2-tss`) development files.  Then:

```sh
autoconf
./configure
make
make check
sudo make install
```

`make check` uses a temporary software TPM when `swtpm` is installed,
and python-fido2 1.x, when installed, as an independent FIDO2 client and
relying party.  See the file `INSTALL` for details.

## Setting up

`sudo make install` creates the `gkey` account and makes both programs
set-group-ID.  Then:

```sh
sudo modprobe uhid
sudo udevadm control --reload
sudo udevadm trigger --subsystem-match=tpmrm --subsystem-match=misc
sudo gpasswd -d "$USER" gkey; sudo gpasswd -d "$USER" tss  # then log in again
systemctl --user enable --now gkey.service
```

Nobody should be in the `gkey` or `tss` groups.

The manual (`info gkey`, or `doc/gkey.texi`) explains the setup, the
security model and the options of both programs.

## Licence

gkey is free software, released under the GNU General Public License,
version 3 or later.  See the file `COPYING`.

Report bugs at <https://github.com/Krishap-s/gkey/issues>.
