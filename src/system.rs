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
    /// A logind session.
    Session(String),
    /// A client of the system bus, identified by its unique name.
    BusName(String),
}

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
            Subject::Session(id) => {
                subject_details.insert("session-id", Value::from(id.as_str()));
                "unix-session"
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
