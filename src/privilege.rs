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

//! Running with the privileges of the `gkey` account.
//!
//! Only the `gkey` account may open the TPM (`/dev/tpmrm0`, through an
//! ACL set by udev) and `/dev/uhid`, and polkit trusts it, as the owner
//! of gkey's actions, to describe each request in the authentication
//! dialog.  `gkey-service` and `gkey` are installed set-user-ID
//! `gkey`.  Each program opens its devices and connects to the system
//! bus first, then drops back to the user for good, keeping only the
//! open file descriptors.  The bus remembers the identity a client had
//! when it connected, so polkit still sees the connection as `gkey`.
//! Files are only ever accessed with the user's own permissions.  The
//! kernel protects set-user-ID processes from being debugged by other
//! processes of the user.
//!
//! Anyone can run these programs with any arguments and environment,
//! so when running set-user-ID they refuse the options and ignore the
//! environment variables that would let the caller choose a different
//! TPM, device, consent method or system bus.

use std::ffi::CString;

use crate::prelude::*;

/// Name of the account the programs are installed set-user-ID to.
/// `make` sets it from `configure --with-gkey-user`.
pub const GKEY_USER: &str = match option_env!("GKEY_USER") {
    Some(user) => user,
    None => "gkey",
};

/// Group that distributions grant TPM access to.
const TSS_GROUP: &str = "tss";

/// Environment variables that must not influence a set-user-ID
/// process: TPM connection settings, TPM library settings (logging to
/// files, configuration paths) and the address of the system bus.
fn is_unsafe_variable(name: &str) -> bool {
    matches!(
        name,
        "GKEY_TCTI" | "TPM2TOOLS_TCTI" | "TCTI" | "DBUS_SYSTEM_BUS_ADDRESS"
    ) || name.starts_with("TSS2_")
}

/// Whether this process runs with privileges it did not have before
/// exec, that is set-user-ID (or set-group-ID).
pub fn is_privileged() -> bool {
    // SAFETY: these calls only read process attributes.
    unsafe {
        libc::getauxval(libc::AT_SECURE) != 0
            || libc::geteuid() != libc::getuid()
            || libc::getegid() != libc::getgid()
    }
}

/// Remove the environment variables that must not influence a
/// privileged process.  Must be called before any other thread is
/// started.
pub fn sanitize_environment() {
    let names: Vec<_> = std::env::vars_os()
        .filter_map(|(name, _)| name.into_string().ok())
        .filter(|name| is_unsafe_variable(name))
        .collect();
    for name in names {
        std::env::remove_var(name);
    }
}

/// Give up the privileged account (and group, if any) for good, in
/// every thread, and check that they are gone.
pub fn drop_privileges() -> Result<()> {
    let failed = |what: &str| {
        Error::Generic(format!(
            "cannot drop the {GKEY_USER} {what}: {}",
            std::io::Error::last_os_error()
        ))
    };
    // SAFETY: these calls only change or read process credentials;
    // glibc applies setresgid and setresuid to every thread.  The group
    // goes first, while the process may still change it.
    unsafe {
        let gid = libc::getgid();
        if libc::setresgid(gid, gid, gid) != 0 {
            return Err(failed("group"));
        }
        let uid = libc::getuid();
        if libc::setresuid(uid, uid, uid) != 0 {
            return Err(failed("account"));
        }
        let (mut ru, mut eu, mut su) = (0, 0, 0);
        let (mut rg, mut eg, mut sg) = (0, 0, 0);
        if libc::getresuid(&mut ru, &mut eu, &mut su) != 0
            || libc::getresgid(&mut rg, &mut eg, &mut sg) != 0
            || [ru, eu, su] != [uid; 3]
            || [rg, eg, sg] != [gid; 3]
        {
            return Err(Error::Generic(format!(
                "the {GKEY_USER} privileges were not dropped"
            )));
        }
    }
    Ok(())
}

fn group_id(name: &str) -> Option<libc::gid_t> {
    let name = CString::new(name).ok()?;
    let mut buf = vec![0 as libc::c_char; 16384];
    // SAFETY: getgrnam_r writes into the buffers given to it.
    unsafe {
        let mut group: libc::group = std::mem::zeroed();
        let mut result: *mut libc::group = std::ptr::null_mut();
        let rc = libc::getgrnam_r(
            name.as_ptr(),
            &mut group,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        );
        (rc == 0 && !result.is_null()).then_some(group.gr_gid)
    }
}

/// The groups of the user that give direct access to the TPM.
/// Programs running as a user who belongs to them can use the TPM
/// without gkey, which defeats its protection.
pub fn privileged_memberships() -> Vec<&'static str> {
    // SAFETY: getgroups fills a buffer of the size it reports.
    let groups = unsafe {
        let count = libc::getgroups(0, std::ptr::null_mut());
        let mut groups = vec![0 as libc::gid_t; count.max(0) as usize];
        let count = libc::getgroups(groups.len() as libc::c_int, groups.as_mut_ptr());
        groups.truncate(count.max(0) as usize);
        groups.push(libc::getgid());
        groups
    };
    [TSS_GROUP]
        .into_iter()
        .filter(|name| group_id(name).is_some_and(|gid| groups.contains(&gid)))
        .collect()
}

/// A warning to show if the user belongs to a group that gives direct
/// TPM or UHID access.
pub fn membership_warning() -> Option<String> {
    let groups = privileged_memberships();
    (!groups.is_empty()).then(|| {
        format!(
            "you belong to the group(s) {}; programs running as you can use the TPM \
             directly, so gkey cannot protect your passkeys from them",
            groups.join(", ")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_variables() {
        for name in [
            "GKEY_TCTI",
            "TPM2TOOLS_TCTI",
            "TCTI",
            "DBUS_SYSTEM_BUS_ADDRESS",
            "TSS2_LOG",
            "TSS2_LOGFILE",
            "TSS2_FAPICONF",
        ] {
            assert!(is_unsafe_variable(name), "{name}");
        }
        for name in ["HOME", "XDG_DATA_HOME", "GKEY_LOG", "PATH"] {
            assert!(!is_unsafe_variable(name), "{name}");
        }
    }

    #[test]
    fn unprivileged_test_run() {
        // The test suite does not run set-user-ID.
        assert!(!is_privileged());
        // Dropping to the real user and group is then a no-op that
        // succeeds.
        drop_privileges().unwrap();
    }
}
