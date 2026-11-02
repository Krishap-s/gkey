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

//! gkey is a FIDO2 (CTAP 2.0) authenticator for GNU/Linux whose root
//! of trust is the Trusted Platform Module.
//!
//! The authenticator exposes itself to relying parties (web browsers)
//! as a virtual USB HID security key created through the kernel's
//! UHID interface.  Every credential private key is generated inside
//! the TPM under a storage primary key and never leaves it in the
//! clear; the metadata describing the credentials is encrypted with a
//! key that is sealed to the same TPM.

pub mod ctap2;
pub mod ctaphid;
mod error;
pub mod getopt;
pub mod keystore;
pub mod prelude;
pub mod tpm;
pub mod uhid;
pub mod verify;

pub use error::Error;

/// Name of the package, used in `--version` output.
pub const PACKAGE: &str = "gkey";

/// Version of the package.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Address to which bug reports should be sent.
pub const PACKAGE_BUGREPORT: &str = "https://github.com/Krishap-s/gkey/issues";

/// Print version information in the format required by the GNU
/// coding standards.
pub fn print_version(program: &str) {
    println!("{program} ({PACKAGE}) {VERSION}");
    println!("Copyright (C) 2026 Krishap");
    println!(
        "License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.\n\
         This is free software: you are free to change and redistribute it.\n\
         There is NO WARRANTY, to the extent permitted by law."
    );
}
