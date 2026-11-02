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
//! gkey asks polkit whether its own process may perform one of the
//! actions of gkey's policy.  polkit maps a process of a user service,
//! which is outside any login session, to the user's graphical session,
//! so the authentication agent of the desktop asks for the user's
//! password (through PAM) and gkey never sees it.  For a program run
//! from a terminal without such an agent, [`TtyAgent`] answers in the
//! terminal.
//!
//! polkit lets only root and the owner of an action pass details, such
//! as the message the dialog shows.  The programs connect to the bus
//! while running set-user-ID `gkey`, the owner of gkey's actions, so
//! they may describe each request; the bus keeps that identity after
//! they drop back to the user.  Run otherwise, as in development, the
//! dialog shows the fixed message of the action.

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
/// polkit action authorizing the commands of the `gkey` program.
pub const ACTION_MANAGE: &str = "io.github.krishap_s.gkey.manage";

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
    /// Whether polkit accepts details from this connection.
    trusted: bool,
}

impl Polkit {
    /// Connect to the system bus.  Must be called from within a
    /// multi-threaded tokio runtime, which keeps serving the
    /// connection, and, in a set-user-ID program, before dropping its
    /// privileges, so that the bus records the connection as the
    /// owner of gkey's actions.
    pub async fn connect() -> Result<Polkit> {
        // SAFETY: these calls only read process attributes.
        let trusted = unsafe { libc::geteuid() == 0 || libc::geteuid() != libc::getuid() };
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
            trusted,
        })
    }

    async fn authority(&self) -> Result<Proxy<'_>> {
        Proxy::new(&self.connection, POLKIT, POLKIT_PATH, POLKIT_INTERFACE)
            .await
            .map_err(bus_error)
    }

    async fn check_async(
        &self,
        action: &str,
        message: &str,
        cancellation_id: &str,
    ) -> Result<bool> {
        let mut subject: HashMap<&str, Value> = HashMap::new();
        subject.insert("pid", Value::from(self.pid));
        subject.insert("start-time", Value::from(self.start_time));
        // Untrusted callers may not pass details at all.
        let mut details: HashMap<&str, &str> = HashMap::new();
        if self.trusted {
            details.insert("polkit.message", message);
        }
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
    /// it ask the user with `message` when polkit trusts this
    /// connection.  Returns `None` if `cancel` became set, in which case
    /// the request is withdrawn.
    pub fn check(&self, action: &str, message: &str, cancel: &AtomicBool) -> Result<Option<bool>> {
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
                .block_on(self.check_async(action, message, &cancellation_id));
            done.store(true, Ordering::Relaxed);
            result
        });
        if cancel.load(Ordering::Relaxed) {
            return Ok(None);
        }
        result.map(Some)
    }
}

/// Make text from a web site safe to show in an authentication dialog:
/// some agents render markup, and control characters could disguise
/// the request.  Keeps at most `max` characters.
pub fn display_text(text: &str, max: usize) -> String {
    let mut out: String = text
        .chars()
        .map(|c| match c {
            '<' => '\u{2039}',
            '>' => '\u{203a}',
            '&' => '+',
            c if c.is_control() => ' ',
            c => c,
        })
        .take(max)
        .collect();
    if text.chars().count() > max {
        out.push('\u{2026}');
    }
    out
}

/// polkit's text mode authentication agent, for programs run from a
/// terminal.  It only answers when no graphical agent serves the
/// user's session, and stops when dropped.
pub struct TtyAgent(Option<std::process::Child>);

impl TtyAgent {
    /// Start `pkttyagent` for this process if standard input is a
    /// terminal, and wait until it is registered with polkit.  Must be
    /// called after dropping privileges.
    pub fn start(polkit: &Polkit) -> TtyAgent {
        // SAFETY: isatty only inspects the descriptor.
        if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
            return TtyAgent(None);
        }
        let mut fds = [0; 2];
        // SAFETY: pipe2 writes two descriptors into the array.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return TtyAgent(None);
        }
        let (read_end, write_end) = (fds[0], fds[1]);
        let mut command = std::process::Command::new("pkttyagent");
        command
            .arg("--process")
            .arg(format!("{},{}", polkit.pid, polkit.start_time))
            .arg("--fallback")
            .arg("--notify-fd")
            .arg("3");
        use std::os::unix::process::CommandExt;
        // SAFETY: dup2 is async-signal-safe; it gives the agent the
        // write end of the pipe as descriptor 3, without close-on-exec.
        unsafe {
            command.pre_exec(move || {
                let ok = if write_end == 3 {
                    libc::fcntl(3, libc::F_SETFD, 0) == 0
                } else {
                    libc::dup2(write_end, 3) >= 0
                };
                if ok {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        let child = command.spawn();
        // SAFETY: closing our copy of the write end, then waiting for
        // the agent to close its copy once registered (or to exit).
        unsafe {
            libc::close(write_end);
            let mut byte = 0u8;
            while libc::read(read_end, &mut byte as *mut u8 as *mut libc::c_void, 1) > 0 {}
            libc::close(read_end);
        }
        match child {
            Ok(child) => TtyAgent(Some(child)),
            Err(err) => {
                log::debug!("cannot start pkttyagent: {err}");
                TtyAgent(None)
            }
        }
    }
}

impl Drop for TtyAgent {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{display_text, parse_start_time};

    #[test]
    fn sanitizes_display_text() {
        assert_eq!(display_text("example.org", 64), "example.org");
        assert_eq!(
            display_text("<b>evil</b>&\u{1b}[31m", 64),
            "\u{2039}b\u{203a}evil\u{2039}/b\u{203a}+ [31m"
        );
        assert_eq!(display_text("abcdef", 3), "abc\u{2026}");
    }

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
