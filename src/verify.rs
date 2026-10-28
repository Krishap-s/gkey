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

//! User presence and user verification.
//!
//! A FIDO authenticator must obtain the consent of the user (user
//! presence) before every operation, and may verify the identity of
//! the user (user verification).  gkey offers two methods:
//!
//! * `polkit` (the default): the authentication agent of the user's
//!   desktop session asks for their password, through PAM, for both
//!   presence and verification.  The service never sees the password.
//!
//! * `command`: an external program is run, with the environment
//!   variable `GKEY_REQUEST` set to `presence` or `verification`,
//!   `GKEY_DESCRIPTION` describing the request and `GKEY_UID` naming
//!   the user.  Exit status zero grants the request.
//!
//! Either way, the operation is abandoned as soon as the host cancels
//! the request.

use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::prelude::*;
use crate::system::{Subject, SystemBus, User, ACTION_USE};

/// Kind of consent requested from the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Presence,
    Verification,
}

/// Outcome of a request for consent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Granted,
    Denied,
    Cancelled,
}

/// How to obtain consent.
#[derive(Clone)]
pub enum Method {
    /// Ask polkit, which authenticates the user of the session.
    Polkit(SystemBus),
    /// An external command, run with `/bin/sh -c`.
    Command(String),
}

/// Obtains user presence and user verification.
#[derive(Clone)]
pub struct Verifier {
    pub method: Method,
}

const POLL_INTERVAL: Duration = Duration::from_millis(50);

impl Verifier {
    /// Ask `user` for consent of the given `kind`.
    pub fn ask(
        &self,
        kind: Kind,
        description: &str,
        user: &User,
        cancel: &AtomicBool,
    ) -> Result<Outcome> {
        if cancel.load(Ordering::Relaxed) {
            return Ok(Outcome::Cancelled);
        }
        let outcome = match &self.method {
            Method::Command(command) => run_command(command, kind, description, user, cancel)?,
            Method::Polkit(bus) => {
                let Some(session) = &user.session else {
                    return Err(Error::Generic(format!(
                        "user {} has no session to ask for consent",
                        user.uid
                    )));
                };
                // Presence and verification are both a password
                // prompt: polkit cannot merely ask for confirmation.
                bus.check_authorization(
                    &Subject::Session(session.clone()),
                    ACTION_USE,
                    description,
                    cancel,
                )?
            }
        };
        if cancel.load(Ordering::Relaxed) {
            return Ok(Outcome::Cancelled);
        }
        Ok(outcome)
    }
}

fn run_command(
    command: &str,
    kind: Kind,
    description: &str,
    user: &User,
    cancel: &AtomicBool,
) -> Result<Outcome> {
    let request = match kind {
        Kind::Presence => "presence",
        Kind::Verification => "verification",
    };
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .env("GKEY_REQUEST", request)
        .env("GKEY_DESCRIPTION", description)
        .env("GKEY_UID", user.uid.to_string())
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| Error::Generic(format!("cannot run '{command}': {e}")))?;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(if status.success() {
                Outcome::Granted
            } else {
                Outcome::Denied
            });
        }
        if cancel.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(Outcome::Cancelled);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_method() {
        let cancel = AtomicBool::new(false);
        let user = User {
            uid: 1000,
            session: None,
        };
        let yes = Verifier {
            method: Method::Command(
                "test \"$GKEY_REQUEST\" = presence && test \"$GKEY_UID\" = 1000".into(),
            ),
        };
        assert_eq!(
            yes.ask(Kind::Presence, "x", &user, &cancel).unwrap(),
            Outcome::Granted
        );
        assert_eq!(
            yes.ask(Kind::Verification, "x", &user, &cancel).unwrap(),
            Outcome::Denied
        );
        cancel.store(true, Ordering::Relaxed);
        assert_eq!(
            yes.ask(Kind::Presence, "x", &user, &cancel).unwrap(),
            Outcome::Cancelled
        );
    }
}
