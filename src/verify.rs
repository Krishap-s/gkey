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
//! * `pam` (the default): presence is a confirmation dialog shown with
//!   GnuPG's pinentry; verification authenticates the user through
//!   PAM, so any PAM module (password, fingerprint, ...) can be used.
//!   PAM prompts are relayed through pinentry.
//!
//! * `command`: an external program is run, with the environment
//!   variable `GKEY_REQUEST` set to `presence` or `verification` and
//!   `GKEY_DESCRIPTION` describing the request.  Exit status zero
//!   grants the request.
//!
//! Either way, the operation is abandoned as soon as the host cancels
//! the request.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::prelude::*;

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
#[derive(Clone, Debug)]
pub enum Method {
    /// PAM for verification, pinentry for presence.
    Pam { service: String, pinentry: String },
    /// An external command, run with `/bin/sh -c`.
    Command(String),
}

/// Obtains user presence and user verification.
#[derive(Clone, Debug)]
pub struct Verifier {
    pub method: Method,
}

const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Kill `child` if `cancel` becomes set before `done` does.
fn watch(child_pid: u32, cancel: &AtomicBool, done: &AtomicBool) {
    while !done.load(Ordering::Relaxed) {
        if cancel.load(Ordering::Relaxed) {
            // SAFETY: sending a signal has no memory safety concerns.
            unsafe {
                libc::kill(child_pid as libc::pid_t, libc::SIGTERM);
            }
            return;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

impl Verifier {
    /// Ask the user for consent of the given `kind`.
    pub fn ask(&self, kind: Kind, description: &str, cancel: &AtomicBool) -> Result<Outcome> {
        if cancel.load(Ordering::Relaxed) {
            return Ok(Outcome::Cancelled);
        }
        let outcome = match (&self.method, kind) {
            (Method::Command(command), _) => run_command(command, kind, description, cancel)?,
            (Method::Pam { pinentry, .. }, Kind::Presence) => {
                confirm(pinentry, description, cancel)?
            }
            (Method::Pam { service, pinentry }, Kind::Verification) => {
                pam_verify(service, pinentry, description, cancel)?
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

/// A pinentry process speaking the Assuan protocol.
struct Pinentry {
    child: Child,
    reader: BufReader<std::process::ChildStdout>,
}

/// Percent-escape an Assuan command argument.
fn assuan_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '%' => out.push_str("%25"),
            '\n' => out.push_str("%0A"),
            '\r' => out.push_str("%0D"),
            c => out.push(c),
        }
    }
    out
}

/// Decode percent-escapes in an Assuan data line.
fn assuan_unescape(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    let mut i = 0;
    while i < value.len() {
        if value[i] == b'%' && i + 2 < value.len() {
            if let Ok(byte) = u8::from_str_radix(&String::from_utf8_lossy(&value[i + 1..i + 3]), 16)
            {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(value[i]);
        i += 1;
    }
    out
}

/// Result of an Assuan transaction.
enum Reply {
    Ok(Zeroizing<Vec<u8>>),
    Err(String),
}

impl Pinentry {
    fn start(program: &str) -> Result<Pinentry> {
        let mut child = Command::new(program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| Error::Generic(format!("cannot run '{program}': {e}")))?;
        let stdout = child.stdout.take().expect("piped stdout");
        let mut pinentry = Pinentry {
            child,
            reader: BufReader::new(stdout),
        };
        match pinentry.read_reply()? {
            Reply::Ok(_) => Ok(pinentry),
            Reply::Err(err) => Err(Error::Generic(format!("pinentry: {err}"))),
        }
    }

    fn read_reply(&mut self) -> Result<Reply> {
        let mut data = Zeroizing::new(Vec::new());
        loop {
            let mut line = Zeroizing::new(Vec::new());
            if self.reader.read_until(b'\n', &mut line)? == 0 {
                return Err(Error::Generic("pinentry exited unexpectedly".into()));
            }
            while line.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
                line.pop();
            }
            if line.as_slice() == b"OK" || line.starts_with(b"OK ") {
                return Ok(Reply::Ok(data));
            }
            if line.starts_with(b"ERR") {
                return Ok(Reply::Err(
                    String::from_utf8_lossy(&line[3..]).trim().to_string(),
                ));
            }
            if let Some(rest) = line.strip_prefix(b"D ") {
                data.extend_from_slice(&assuan_unescape(rest));
            }
            // Status ("S") and comment ("#") lines are ignored.
        }
    }

    fn command(&mut self, command: &str) -> Result<Reply> {
        let stdin = self.child.stdin.as_mut().expect("piped stdin");
        stdin.write_all(command.as_bytes())?;
        stdin.write_all(b"\n")?;
        stdin.flush()?;
        self.read_reply()
    }

    fn set(&mut self, command: &str, value: &str) -> Result<()> {
        match self.command(&format!("{command} {}", assuan_escape(value)))? {
            Reply::Ok(_) => Ok(()),
            Reply::Err(err) => Err(Error::Generic(format!("pinentry: {command}: {err}"))),
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Pinentry {
    fn drop(&mut self) {
        if let Some(stdin) = self.child.stdin.as_mut() {
            let _ = stdin.write_all(b"BYE\n");
        }
        self.child.stdin = None;
        let _ = self.child.wait();
    }
}

/// Run `f` with a fresh pinentry, killing it if the request is
/// cancelled.
fn with_pinentry<T>(
    program: &str,
    cancel: &AtomicBool,
    f: impl FnOnce(&mut Pinentry) -> Result<T>,
) -> Result<T> {
    let mut pinentry = Pinentry::start(program)?;
    let done = AtomicBool::new(false);
    let pid = pinentry.pid();
    std::thread::scope(|scope| {
        scope.spawn(|| watch(pid, cancel, &done));
        let result = pinentry
            .set("SETTITLE", "gkey")
            .and_then(|_| f(&mut pinentry));
        done.store(true, Ordering::Relaxed);
        result
    })
}

fn confirm(program: &str, description: &str, cancel: &AtomicBool) -> Result<Outcome> {
    let result = with_pinentry(program, cancel, |pinentry| {
        pinentry.set("SETDESC", description)?;
        pinentry.set("SETOK", "Allow")?;
        pinentry.set("SETCANCEL", "Deny")?;
        pinentry.command("CONFIRM")
    });
    match result {
        Ok(Reply::Ok(_)) => Ok(Outcome::Granted),
        Ok(Reply::Err(_)) => Ok(Outcome::Denied),
        Err(_) if cancel.load(Ordering::Relaxed) => Ok(Outcome::Cancelled),
        Err(err) => Err(err),
    }
}

/// Ask for a secret with pinentry.  `None` means the user refused.
fn get_secret(
    program: &str,
    description: &str,
    prompt: &str,
    cancel: &AtomicBool,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let result = with_pinentry(program, cancel, |pinentry| {
        pinentry.set("SETDESC", description)?;
        pinentry.set("SETPROMPT", prompt)?;
        pinentry.command("GETPIN")
    })?;
    match result {
        Reply::Ok(secret) => Ok(Some(secret)),
        Reply::Err(_) => Ok(None),
    }
}

// Minimal bindings to Linux-PAM, see pam_start(3).

const PAM_SUCCESS: c_int = 0;
const PAM_BUF_ERR: c_int = 5;
const PAM_CONV_ERR: c_int = 19;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;
const PAM_ERROR_MSG: c_int = 3;
const PAM_TEXT_INFO: c_int = 4;

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

type ConvFn =
    extern "C" fn(c_int, *mut *const PamMessage, *mut *mut PamResponse, *mut c_void) -> c_int;

#[repr(C)]
struct PamConv {
    conv: ConvFn,
    appdata_ptr: *mut c_void,
}

#[link(name = "pam")]
extern "C" {
    fn pam_start(
        service: *const c_char,
        user: *const c_char,
        conv: *const PamConv,
        pamh: *mut *mut c_void,
    ) -> c_int;
    fn pam_authenticate(pamh: *mut c_void, flags: c_int) -> c_int;
    fn pam_acct_mgmt(pamh: *mut c_void, flags: c_int) -> c_int;
    fn pam_end(pamh: *mut c_void, status: c_int) -> c_int;
    fn pam_strerror(pamh: *mut c_void, errnum: c_int) -> *const c_char;
}

struct Conversation<'a> {
    pinentry: &'a str,
    description: &'a str,
    cancel: &'a AtomicBool,
    error: Option<Error>,
}

extern "C" fn converse(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata: *mut c_void,
) -> c_int {
    if num_msg <= 0 || msg.is_null() || resp.is_null() || appdata.is_null() {
        return PAM_CONV_ERR;
    }
    // SAFETY: PAM passes back the pointer given to pam_start, which
    // points to a live Conversation for the duration of the call.
    let conversation = unsafe { &mut *(appdata as *mut Conversation) };
    let count = num_msg as usize;
    // SAFETY: PAM frees the responses with free(3), so they must be
    // allocated with the C allocator.
    let responses =
        unsafe { libc::calloc(count, std::mem::size_of::<PamResponse>()) } as *mut PamResponse;
    if responses.is_null() {
        return PAM_BUF_ERR;
    }
    let fail = |code| {
        for i in 0..count {
            // SAFETY: `responses` holds `count` initialized entries.
            unsafe {
                let r = &mut *responses.add(i);
                if !r.resp.is_null() {
                    let len = libc::strlen(r.resp);
                    std::ptr::write_bytes(r.resp, 0, len);
                    libc::free(r.resp as *mut c_void);
                }
            }
        }
        // SAFETY: allocated with calloc above.
        unsafe { libc::free(responses as *mut c_void) };
        code
    };
    for i in 0..count {
        // SAFETY: Linux-PAM passes an array of `num_msg` pointers.
        let message = unsafe { &**msg.add(i) };
        let text = if message.msg.is_null() {
            String::new()
        } else {
            // SAFETY: PAM messages are NUL terminated strings.
            unsafe { CStr::from_ptr(message.msg) }
                .to_string_lossy()
                .trim()
                .to_string()
        };
        match message.msg_style {
            PAM_PROMPT_ECHO_OFF | PAM_PROMPT_ECHO_ON => {
                let secret = match get_secret(
                    conversation.pinentry,
                    conversation.description,
                    &text,
                    conversation.cancel,
                ) {
                    Ok(Some(secret)) => secret,
                    Ok(None) => return fail(PAM_CONV_ERR),
                    Err(err) => {
                        conversation.error = Some(err);
                        return fail(PAM_CONV_ERR);
                    }
                };
                let Ok(secret) = CString::new(secret.to_vec()) else {
                    return fail(PAM_CONV_ERR);
                };
                let secret = Zeroizing::new(secret.into_bytes_with_nul());
                // SAFETY: strdup copies the NUL terminated secret
                // into memory that PAM will free.
                let copy = unsafe { libc::strdup(secret.as_ptr() as *const c_char) };
                if copy.is_null() {
                    return fail(PAM_BUF_ERR);
                }
                // SAFETY: index within the allocated array.
                unsafe { (*responses.add(i)).resp = copy };
            }
            PAM_ERROR_MSG => log::warn!("PAM: {text}"),
            PAM_TEXT_INFO => log::info!("PAM: {text}"),
            _ => return fail(PAM_CONV_ERR),
        }
    }
    // SAFETY: `resp` is a valid out pointer supplied by PAM.
    unsafe { *resp = responses };
    PAM_SUCCESS
}

/// Return the login name of the user running this process.
pub fn current_user() -> Result<String> {
    let mut buf = vec![0 as c_char; 4096];
    // SAFETY: getpwuid_r writes into the buffers given to it.
    unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = libc::getpwuid_r(
            libc::getuid(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        );
        if rc != 0 || result.is_null() {
            return Err(Error::Generic("cannot determine the current user".into()));
        }
        Ok(CStr::from_ptr(pwd.pw_name).to_string_lossy().into_owned())
    }
}

fn pam_verify(
    service: &str,
    pinentry: &str,
    description: &str,
    cancel: &AtomicBool,
) -> Result<Outcome> {
    let user = current_user()?;
    let c_service = CString::new(service).map_err(|_| Error::Generic("bad PAM service".into()))?;
    let c_user = CString::new(user).map_err(|_| Error::Generic("bad user name".into()))?;
    let mut conversation = Conversation {
        pinentry,
        description,
        cancel,
        error: None,
    };
    let conv = PamConv {
        conv: converse,
        appdata_ptr: &mut conversation as *mut Conversation as *mut c_void,
    };
    let mut handle: *mut c_void = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the whole PAM transaction,
    // which ends with pam_end below.
    let rc = unsafe {
        let mut rc = pam_start(c_service.as_ptr(), c_user.as_ptr(), &conv, &mut handle);
        if rc == PAM_SUCCESS {
            rc = pam_authenticate(handle, 0);
            if rc == PAM_SUCCESS {
                rc = pam_acct_mgmt(handle, 0);
            }
            if rc != PAM_SUCCESS {
                let message = CStr::from_ptr(pam_strerror(handle, rc)).to_string_lossy();
                log::info!("PAM: {message}");
            }
            pam_end(handle, rc);
        }
        rc
    };
    if let Some(err) = conversation.error {
        if cancel.load(Ordering::Relaxed) {
            return Ok(Outcome::Cancelled);
        }
        return Err(err);
    }
    if rc == PAM_SUCCESS {
        Ok(Outcome::Granted)
    } else {
        Ok(Outcome::Denied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assuan_round_trip() {
        assert_eq!(assuan_escape("a%b\nc"), "a%25b%0Ac");
        assert_eq!(assuan_unescape(b"a%25b%0Ac"), b"a%b\nc");
        assert_eq!(assuan_unescape(b"100%"), b"100%");
    }

    #[test]
    fn command_method() {
        let cancel = AtomicBool::new(false);
        let yes = Verifier {
            method: Method::Command("test \"$GKEY_REQUEST\" = presence".into()),
        };
        assert_eq!(
            yes.ask(Kind::Presence, "x", &cancel).unwrap(),
            Outcome::Granted
        );
        assert_eq!(
            yes.ask(Kind::Verification, "x", &cancel).unwrap(),
            Outcome::Denied
        );
        cancel.store(true, Ordering::Relaxed);
        assert_eq!(
            yes.ask(Kind::Presence, "x", &cancel).unwrap(),
            Outcome::Cancelled
        );
    }
}
