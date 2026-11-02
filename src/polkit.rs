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

//! Asking polkit for the consent of the user.
//!
//! gkey-service asks polkit whether its own process may perform one of
//! the actions of gkey's policy.  polkit maps a process of a user
//! service, which is outside any login session, to the user's
//! graphical session, so the authentication agent of the desktop asks
//! for the user's password (through PAM) and gkey never sees it.
//!
//! polkit lets unprivileged programs check authorizations only for
//! themselves and without details, so the dialog shows the fixed
//! message of the action, not the name of the web site.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use zbus::zvariant::Value;
use zbus::{Connection, Proxy};

use crate::prelude::*;

/// polkit action authorizing the creation of a passkey.
pub const ACTION_CREATE: &str = "io.github.krishap_s.gkey.create-passkey";
/// polkit action authorizing signing in with a passkey.
pub const ACTION_SIGN_IN: &str = "io.github.krishap_s.gkey.sign-in";
/// polkit action authorizing the deletion of every passkey.
pub const ACTION_RESET: &str = "io.github.krishap_s.gkey.reset";

const POLKIT: &str = "org.freedesktop.PolicyKit1";
const POLKIT_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const POLKIT_INTERFACE: &str = "org.freedesktop.PolicyKit1.Authority";
/// CheckAuthorization flag letting polkit ask the user.
const ALLOW_USER_INTERACTION: u32 = 1;
const POLL_INTERVAL: Duration = Duration::from_millis(50);

fn bus_error(err: zbus::Error) -> Error {
    Error::Generic(format!("polkit: {err}"))
}

/// Parse the start time, in clock ticks since boot, out of the
/// contents of `/proc/PID/stat`.
fn parse_start_time(stat: &str) -> Option<u64> {
    // The command name, in parentheses, may contain spaces; the start
    // time is the 20th field after it.
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// A connection to polkit on the system bus, usable from threads
/// outside of the event loop.
#[derive(Clone)]
pub struct Polkit {
    connection: Connection,
    runtime: tokio::runtime::Handle,
    pid: u32,
    start_time: u64,
}

impl Polkit {
    /// Connect to the system bus.  Must be called from within a
    /// multi-threaded tokio runtime, which keeps serving the
    /// connection.
    pub async fn connect() -> Result<Polkit> {
        let stat = std::fs::read_to_string("/proc/self/stat")?;
        let start_time = parse_start_time(&stat)
            .ok_or_else(|| Error::Generic("cannot parse /proc/self/stat".into()))?;
        let connection = Connection::system()
            .await
            .map_err(|e| Error::Generic(format!("cannot connect to the system bus: {e}")))?;
        Ok(Polkit {
            connection,
            runtime: tokio::runtime::Handle::current(),
            pid: std::process::id(),
            start_time,
        })
    }

    async fn authority(&self) -> Result<Proxy<'_>> {
        Proxy::new(&self.connection, POLKIT, POLKIT_PATH, POLKIT_INTERFACE)
            .await
            .map_err(bus_error)
    }

    async fn check_async(&self, action: &str, cancellation_id: &str) -> Result<bool> {
        let mut subject: HashMap<&str, Value> = HashMap::new();
        subject.insert("pid", Value::from(self.pid));
        subject.insert("start-time", Value::from(self.start_time));
        // Unprivileged callers may not pass details.
        let details: HashMap<&str, &str> = HashMap::new();
        let (authorized, _challenge, _details): (bool, bool, HashMap<String, String>) = self
            .authority()
            .await?
            .call(
                "CheckAuthorization",
                &(
                    ("unix-process", subject),
                    action,
                    details,
                    ALLOW_USER_INTERACTION,
                    cancellation_id,
                ),
            )
            .await
            .map_err(bus_error)?;
        Ok(authorized)
    }

    async fn cancel_async(&self, cancellation_id: &str) -> Result<()> {
        self.authority()
            .await?
            .call::<_, _, ()>("CancelCheckAuthorization", &(cancellation_id,))
            .await
            .map_err(bus_error)
    }

    /// Ask polkit whether this process may perform `action`, letting
    /// it ask the user.  Returns `None` if `cancel` became set, in
    /// which case the request is withdrawn.
    pub fn check(&self, action: &str, cancel: &AtomicBool) -> Result<Option<bool>> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let cancellation_id = format!("gkey-{}", COUNTER.fetch_add(1, Ordering::Relaxed));
        let done = AtomicBool::new(false);
        let result = std::thread::scope(|scope| {
            scope.spawn(|| {
                while !done.load(Ordering::Relaxed) {
                    if cancel.load(Ordering::Relaxed) {
                        if let Err(err) = self.runtime.block_on(self.cancel_async(&cancellation_id))
                        {
                            log::warn!("cannot withdraw the polkit request: {err}");
                        }
                        return;
                    }
                    std::thread::sleep(POLL_INTERVAL);
                }
            });
            let result = self
                .runtime
                .block_on(self.check_async(action, &cancellation_id));
            done.store(true, Ordering::Relaxed);
            result
        });
        if cancel.load(Ordering::Relaxed) {
            return Ok(None);
        }
        result.map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::parse_start_time;

    #[test]
    fn parses_start_time() {
        let stat = "1234 (a (weird) name) S 1 1234 1234 0 -1 4194560 100 0 0 0 \
                    1 2 0 0 20 0 1 0 987654 12345678 300";
        assert_eq!(parse_start_time(stat), Some(987654));
        assert_eq!(parse_start_time("garbage"), None);
        let own = std::fs::read_to_string("/proc/self/stat").unwrap();
        assert!(parse_start_time(&own).is_some());
    }
}
