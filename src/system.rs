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

//! Services of the operating system that gkey relies on, reached over
//! the D-Bus system bus:
//!
//! * systemd-logind, to learn which user sits at the seat, since only
//!   that user can open the HID device the browser talks to;
//! * polkit, to obtain the consent of that user.  The desktop's
//!   polkit authentication agent asks for the user's password, through
//!   PAM, and gkey never sees it.
//!
//! polkit is asked on behalf of a process of the user in their session
//! rather than on behalf of the session itself: polkit's rules engine
//! aborts on session subjects.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use zbus::zvariant::{OwnedObjectPath, Value};
use zbus::{Connection, Proxy};

use crate::prelude::*;
use crate::verify::Outcome;

/// Well known name of gkey-service on the system bus.
pub const SERVICE_NAME: &str = "io.github.krishap_s.Gkey1";
/// Object path of the management interface.
pub const OBJECT_PATH: &str = "/io/github/krishap_s/Gkey1";
/// Name of the management interface.
pub const INTERFACE: &str = "io.github.krishap_s.Gkey1";
/// polkit action authorizing the use of a passkey.
pub const ACTION_USE: &str = "io.github.krishap_s.gkey.use-passkey";
/// polkit action authorizing changes to the stored passkeys.
pub const ACTION_MANAGE: &str = "io.github.krishap_s.gkey.manage";

const POLKIT: &str = "org.freedesktop.PolicyKit1";
const POLKIT_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const POLKIT_INTERFACE: &str = "org.freedesktop.PolicyKit1.Authority";
/// CheckAuthorization flag letting polkit ask the user.
const ALLOW_USER_INTERACTION: u32 = 1;
const LOGIND: &str = "org.freedesktop.login1";
const POLL_INTERVAL: Duration = Duration::from_millis(50);

fn bus_error(err: zbus::Error) -> Error {
    Error::Generic(format!("D-Bus: {err}"))
}

/// The user on whose behalf a request is processed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub uid: u32,
    /// logind session to ask for consent, if known.
    pub session: Option<String>,
}

/// Who asks for consent in a polkit check.
pub enum Subject {
    /// A process, identified by its ID and start time.
    Process { pid: u32, start_time: u64 },
    /// A client of the system bus, identified by its unique name.
    BusName(String),
}

/// A process found in `/proc`.
#[derive(Debug, PartialEq, Eq)]
struct ProcessInfo {
    pid: u32,
    /// Start time, in clock ticks since boot, as polkit expects it.
    start_time: u64,
    cgroup: String,
}

/// Parse the start time out of the contents of `/proc/PID/stat`.
fn parse_start_time(stat: &str) -> Option<u64> {
    // The command name, in parentheses, may contain spaces; the
    // start time is the 20th field after it.
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// Parse the real user ID out of the contents of `/proc/PID/status`.
fn parse_real_uid(status: &str) -> Option<u32> {
    let line = status.lines().find(|l| l.starts_with("Uid:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// Return the processes whose real user is `uid`, oldest first.
fn user_processes(uid: u32) -> Vec<ProcessInfo> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut processes: Vec<ProcessInfo> = entries
        .flatten()
        .filter_map(|entry| {
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            let dir = entry.path();
            let status = std::fs::read_to_string(dir.join("status")).ok()?;
            if parse_real_uid(&status)? != uid {
                return None;
            }
            let stat = std::fs::read_to_string(dir.join("stat")).ok()?;
            Some(ProcessInfo {
                pid,
                start_time: parse_start_time(&stat)?,
                cgroup: std::fs::read_to_string(dir.join("cgroup")).unwrap_or_default(),
            })
        })
        .collect();
    processes.sort_by_key(|p| (p.start_time, p.pid));
    processes
}

/// Most processes to ask logind about when looking for a process of
/// a session whose cgroup does not tell.
const MAX_SESSION_LOOKUPS: usize = 64;

/// A connection to the system bus, usable from threads outside of the
/// event loop.
#[derive(Clone)]
pub struct SystemBus {
    connection: Connection,
    runtime: tokio::runtime::Handle,
}

impl SystemBus {
    /// Connect to the system bus.  Must be called from within a
    /// multi-threaded tokio runtime, which keeps serving the
    /// connection.
    pub async fn connect() -> Result<SystemBus> {
        let connection = Connection::system().await.map_err(bus_error)?;
        Ok(SystemBus {
            connection,
            runtime: tokio::runtime::Handle::current(),
        })
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Return the user of the active session on `seat`, if any.
    pub fn active_user(&self, seat: &str) -> Result<Option<User>> {
        self.runtime.block_on(self.active_user_async(seat))
    }

    async fn active_user_async(&self, seat: &str) -> Result<Option<User>> {
        let seat_path = format!("/org/freedesktop/login1/seat/{seat}");
        let seat = Proxy::new(
            &self.connection,
            LOGIND,
            seat_path.as_str(),
            "org.freedesktop.login1.Seat",
        )
        .await
        .map_err(bus_error)?;
        let (id, path): (String, OwnedObjectPath) = seat
            .get_property("ActiveSession")
            .await
            .map_err(bus_error)?;
        if id.is_empty() {
            return Ok(None);
        }
        let session = Proxy::new(
            &self.connection,
            LOGIND,
            path,
            "org.freedesktop.login1.Session",
        )
        .await
        .map_err(bus_error)?;
        let (uid, _): (u32, OwnedObjectPath) =
            session.get_property("User").await.map_err(bus_error)?;
        let class: String = session.get_property("Class").await.map_err(bus_error)?;
        let active: bool = session.get_property("Active").await.map_err(bus_error)?;
        if class != "user" || !active {
            return Ok(None);
        }
        Ok(Some(User {
            uid,
            session: Some(id),
        }))
    }

    /// Find a process of the user `uid` in the logind session
    /// `session`, to stand for the user in polkit checks.
    pub fn session_process(&self, uid: u32, session: &str) -> Result<Subject> {
        self.runtime
            .block_on(self.session_process_async(uid, session))
    }

    async fn session_process_async(&self, uid: u32, session: &str) -> Result<Subject> {
        let processes = user_processes(uid);
        // systemd-logind puts the processes of session N in the
        // session-N.scope cgroup.
        let scope = format!("/session-{session}.scope");
        let by_cgroup = processes.iter().find(|p| {
            p.cgroup
                .lines()
                .any(|l| l.ends_with(&scope) || l.contains(&format!("{scope}/")))
        });
        if let Some(p) = by_cgroup {
            return Ok(Subject::Process {
                pid: p.pid,
                start_time: p.start_time,
            });
        }
        // Otherwise, as with elogind, ask the session manager.
        let manager = Proxy::new(
            &self.connection,
            LOGIND,
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
        )
        .await
        .map_err(bus_error)?;
        let wanted: OwnedObjectPath = manager
            .call("GetSession", &(session,))
            .await
            .map_err(bus_error)?;
        for p in processes.iter().take(MAX_SESSION_LOOKUPS) {
            let found: zbus::Result<OwnedObjectPath> =
                manager.call("GetSessionByPID", &(p.pid,)).await;
            if found.is_ok_and(|path| path == wanted) {
                return Ok(Subject::Process {
                    pid: p.pid,
                    start_time: p.start_time,
                });
            }
        }
        Err(Error::Generic(format!(
            "cannot find a process of user {uid} in session {session} \
             (is /proc mounted with hidepid?)"
        )))
    }

    /// Ask polkit whether `subject` may perform `action`, letting the
    /// authentication agent of the user show `message`.
    pub async fn check_authorization_async(
        &self,
        subject: &Subject,
        action: &str,
        message: &str,
        cancellation_id: &str,
    ) -> Result<bool> {
        let authority = Proxy::new(&self.connection, POLKIT, POLKIT_PATH, POLKIT_INTERFACE)
            .await
            .map_err(bus_error)?;
        let mut subject_details: HashMap<&str, Value> = HashMap::new();
        let kind = match subject {
            Subject::Process { pid, start_time } => {
                subject_details.insert("pid", Value::from(*pid));
                subject_details.insert("start-time", Value::from(*start_time));
                "unix-process"
            }
            Subject::BusName(name) => {
                subject_details.insert("name", Value::from(name.as_str()));
                "system-bus-name"
            }
        };
        let mut details: HashMap<&str, &str> = HashMap::new();
        details.insert("polkit.message", message);
        let (authorized, _challenge, _details): (bool, bool, HashMap<String, String>) = authority
            .call(
                "CheckAuthorization",
                &(
                    (kind, subject_details),
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

    async fn cancel_check_async(&self, cancellation_id: &str) -> Result<()> {
        let authority = Proxy::new(&self.connection, POLKIT, POLKIT_PATH, POLKIT_INTERFACE)
            .await
            .map_err(bus_error)?;
        authority
            .call::<_, _, ()>("CancelCheckAuthorization", &(cancellation_id,))
            .await
            .map_err(bus_error)
    }

    /// Blocking variant of [`SystemBus::check_authorization_async`]
    /// that withdraws the request when `cancel` becomes set.
    pub fn check_authorization(
        &self,
        subject: &Subject,
        action: &str,
        message: &str,
        cancel: &AtomicBool,
    ) -> Result<Outcome> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let cancellation_id = format!(
            "gkey-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let done = AtomicBool::new(false);
        let result = std::thread::scope(|scope| {
            scope.spawn(|| {
                while !done.load(Ordering::Relaxed) {
                    if cancel.load(Ordering::Relaxed) {
                        if let Err(err) = self
                            .runtime
                            .block_on(self.cancel_check_async(&cancellation_id))
                        {
                            log::warn!("cannot withdraw the polkit request: {err}");
                        }
                        return;
                    }
                    std::thread::sleep(POLL_INTERVAL);
                }
            });
            let result = self.runtime.block_on(self.check_authorization_async(
                subject,
                action,
                message,
                &cancellation_id,
            ));
            done.store(true, Ordering::Relaxed);
            result
        });
        if cancel.load(Ordering::Relaxed) {
            return Ok(Outcome::Cancelled);
        }
        match result? {
            true => Ok(Outcome::Granted),
            false => Ok(Outcome::Denied),
        }
    }

    /// Return the user ID of the system bus client `name`.
    pub async fn caller_uid(&self, name: &str) -> Result<u32> {
        let proxy = zbus::fdo::DBusProxy::new(&self.connection)
            .await
            .map_err(bus_error)?;
        let name = zbus::names::BusName::try_from(name)
            .map_err(|e| Error::Generic(format!("D-Bus: {e}")))?;
        proxy
            .get_connection_unix_user(name)
            .await
            .map_err(|e| Error::Generic(format!("D-Bus: {e}")))
    }
}

/// How to find the user a request is for.
#[derive(Clone)]
pub enum UserSource {
    /// The user of the active session on a seat.
    Seat { bus: SystemBus, seat: String },
    /// Always the given user, without a session.  For testing.
    Fixed(u32),
}

impl UserSource {
    /// Return the user on whose behalf to process a request now.
    pub fn current(&self) -> Result<Option<User>> {
        match self {
            UserSource::Seat { bus, seat } => bus.active_user(seat),
            UserSource::Fixed(uid) => Ok(Some(User {
                uid: *uid,
                session: None,
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_files() {
        let stat = "1234 (a (weird) name) S 1 1234 1234 0 -1 4194560 100 0 0 0 \
                    1 2 0 0 20 0 1 0 987654 12345678 300 18446744073709551615";
        assert_eq!(parse_start_time(stat), Some(987654));
        assert_eq!(parse_start_time("garbage"), None);
        let status = "Name:\tbash\nUid:\t1000\t1001\t1000\t1000\nGid:\t100\n";
        assert_eq!(parse_real_uid(status), Some(1000));
    }

    #[test]
    fn finds_own_processes() {
        // SAFETY: getuid cannot fail.
        let uid = unsafe { libc::getuid() };
        let me = std::process::id();
        let processes = user_processes(uid);
        assert!(processes.iter().any(|p| p.pid == me));
        assert!(processes
            .windows(2)
            .all(|w| w[0].start_time <= w[1].start_time));
    }
}
