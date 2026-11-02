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
//! * `polkit` (the default): polkit's authentication agent, in the
//!   user's desktop session, asks for the user's password, through PAM,
//!   for both presence and verification.  See [`crate::polkit`].
//!
//! * `command`: an external program is run, with the environment
//!   variable `GKEY_REQUEST` set to `presence` or `verification`,
//!   `GKEY_OPERATION` to `create`, `sign-in` or `reset`, and
//!   `GKEY_DESCRIPTION` describing the request.  Exit status zero
//!   grants the request.
//!
//! Either way, the operation is abandoned as soon as the host cancels
//! the request.

use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::polkit::{Polkit, ACTION_CREATE, ACTION_RESET, ACTION_SIGN_IN};
use crate::prelude::*;

/// Kind of consent requested from the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Presence,
    Verification,
}

/// The operation the user consents to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    /// Creating a passkey.
    Create,
    /// Using a passkey to sign in.
    SignIn,
    /// Deleting every passkey.
    Reset,
}

impl Operation {
    fn name(self) -> &'static str {
        match self {
            Operation::Create => "create",
            Operation::SignIn => "sign-in",
            Operation::Reset => "reset",
        }
    }

    fn polkit_action(self) -> &'static str {
        match self {
            Operation::Create => ACTION_CREATE,
            Operation::SignIn => ACTION_SIGN_IN,
            Operation::Reset => ACTION_RESET,
        }
    }
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
    /// Ask polkit.
    Polkit(Polkit),
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
    /// Ask the user for consent of the given `kind` to `operation`.
    pub fn ask(
        &self,
        kind: Kind,
        operation: Operation,
        description: &str,
        cancel: &AtomicBool,
    ) -> Result<Outcome> {
        if cancel.load(Ordering::Relaxed) {
            return Ok(Outcome::Cancelled);
        }
        let outcome = match &self.method {
            Method::Command(command) => run_command(command, kind, operation, description, cancel)?,
            // polkit cannot merely ask for confirmation, so presence
            // and verification are both an authentication.
            Method::Polkit(polkit) => {
                match polkit.check(operation.polkit_action(), description, cancel)? {
                    Some(true) => Outcome::Granted,
                    Some(false) => Outcome::Denied,
                    None => Outcome::Cancelled,
                }
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
    operation: Operation,
    description: &str,
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
        .env("GKEY_OPERATION", operation.name())
        .env("GKEY_DESCRIPTION", description)
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
        let yes = Verifier {
            method: Method::Command(
                "test \"$GKEY_REQUEST\" = presence && test \"$GKEY_OPERATION\" = sign-in".into(),
            ),
        };
        let ask = |kind, operation| yes.ask(kind, operation, "x", &cancel).unwrap();
        assert_eq!(ask(Kind::Presence, Operation::SignIn), Outcome::Granted);
        assert_eq!(ask(Kind::Verification, Operation::SignIn), Outcome::Denied);
        assert_eq!(ask(Kind::Presence, Operation::Create), Outcome::Denied);
        cancel.store(true, Ordering::Relaxed);
        assert_eq!(
            yes.ask(Kind::Presence, Operation::SignIn, "x", &cancel)
                .unwrap(),
            Outcome::Cancelled
        );
    }
}
