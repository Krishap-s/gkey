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

//! Minimal asynchronous interface to the Linux UHID driver.
//!
//! See <https://www.kernel.org/doc/html/latest/hid/uhid.html>.  The
//! layout of `struct uhid_event` is part of the kernel ABI and is
//! encoded here by hand (it is a packed structure in host byte
//! order), which avoids depending on bindings generated at build
//! time.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use tokio::io::unix::AsyncFd;

/// Default path of the UHID character device.
pub const UHID_PATH: &str = "/dev/uhid";

const UHID_DESTROY: u32 = 1;
const UHID_START: u32 = 2;
const UHID_STOP: u32 = 3;
const UHID_OPEN: u32 = 4;
const UHID_CLOSE: u32 = 5;
const UHID_OUTPUT: u32 = 6;
const UHID_GET_REPORT: u32 = 9;
const UHID_GET_REPORT_REPLY: u32 = 10;
const UHID_CREATE2: u32 = 11;
const UHID_INPUT2: u32 = 12;
const UHID_SET_REPORT: u32 = 13;
const UHID_SET_REPORT_REPLY: u32 = 14;

/// Maximum size of a report or report descriptor.
pub const UHID_DATA_MAX: usize = 4096;

/// Size of `struct uhid_event`: the event type followed by the
/// largest member of the union, `struct uhid_create2_req`.
pub const UHID_EVENT_SIZE: usize = 4 + 128 + 64 + 64 + 2 + 2 + 4 * 4 + UHID_DATA_MAX;

/// Bus type of a USB device, from `<linux/input.h>`.
pub const BUS_USB: u16 = 0x03;

/// Parameters of a new HID device.
pub struct CreateParams {
    pub name: String,
    pub phys: String,
    pub uniq: String,
    pub bus: u16,
    pub vendor: u32,
    pub product: u32,
    pub version: u32,
    pub country: u32,
    pub report_descriptor: Vec<u8>,
}

/// Events sent by the kernel to the device.
#[derive(Debug, PartialEq, Eq)]
pub enum OutputEvent {
    Start,
    Stop,
    Open,
    Close,
    /// An output report written by the host, without the report
    /// number prefix.
    Output(Vec<u8>),
    GetReport {
        id: u32,
    },
    SetReport {
        id: u32,
    },
    Unknown(u32),
}

fn put_str(buf: &mut [u8], value: &str) {
    let bytes = value.as_bytes();
    // Always leave room for the terminating NUL byte.
    let len = bytes.len().min(buf.len() - 1);
    buf[..len].copy_from_slice(&bytes[..len]);
}

fn get_u16(buf: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes([buf[at], buf[at + 1]])
}

fn get_u32(buf: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

/// Encode a `UHID_CREATE2` request.
pub fn encode_create(params: &CreateParams) -> io::Result<Vec<u8>> {
    if params.report_descriptor.len() > UHID_DATA_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "report descriptor too large",
        ));
    }
    let mut ev = vec![0u8; UHID_EVENT_SIZE];
    ev[0..4].copy_from_slice(&UHID_CREATE2.to_ne_bytes());
    put_str(&mut ev[4..132], &params.name);
    put_str(&mut ev[132..196], &params.phys);
    put_str(&mut ev[196..260], &params.uniq);
    ev[260..262].copy_from_slice(&(params.report_descriptor.len() as u16).to_ne_bytes());
    ev[262..264].copy_from_slice(&params.bus.to_ne_bytes());
    ev[264..268].copy_from_slice(&params.vendor.to_ne_bytes());
    ev[268..272].copy_from_slice(&params.product.to_ne_bytes());
    ev[272..276].copy_from_slice(&params.version.to_ne_bytes());
    ev[276..280].copy_from_slice(&params.country.to_ne_bytes());
    ev[280..280 + params.report_descriptor.len()].copy_from_slice(&params.report_descriptor);
    Ok(ev)
}

/// Encode a `UHID_INPUT2` request carrying an input report.
pub fn encode_input(data: &[u8]) -> io::Result<Vec<u8>> {
    if data.len() > UHID_DATA_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "report too large",
        ));
    }
    let mut ev = vec![0u8; 4 + 2 + data.len()];
    ev[0..4].copy_from_slice(&UHID_INPUT2.to_ne_bytes());
    ev[4..6].copy_from_slice(&(data.len() as u16).to_ne_bytes());
    ev[6..].copy_from_slice(data);
    Ok(ev)
}

fn encode_get_report_reply(id: u32, err: u16) -> Vec<u8> {
    let mut ev = vec![0u8; 4 + 4 + 2 + 2];
    ev[0..4].copy_from_slice(&UHID_GET_REPORT_REPLY.to_ne_bytes());
    ev[4..8].copy_from_slice(&id.to_ne_bytes());
    ev[8..10].copy_from_slice(&err.to_ne_bytes());
    ev
}

fn encode_set_report_reply(id: u32, err: u16) -> Vec<u8> {
    let mut ev = vec![0u8; 4 + 4 + 2];
    ev[0..4].copy_from_slice(&UHID_SET_REPORT_REPLY.to_ne_bytes());
    ev[4..8].copy_from_slice(&id.to_ne_bytes());
    ev[8..10].copy_from_slice(&err.to_ne_bytes());
    ev
}

/// Decode an event read from the UHID device.
pub fn decode_output(buf: &[u8]) -> io::Result<OutputEvent> {
    if buf.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short UHID event",
        ));
    }
    let event = match get_u32(buf, 0) {
        UHID_START => OutputEvent::Start,
        UHID_STOP => OutputEvent::Stop,
        UHID_OPEN => OutputEvent::Open,
        UHID_CLOSE => OutputEvent::Close,
        UHID_OUTPUT => {
            // struct uhid_output_req { u8 data[4096]; u16 size; u8 rtype; }
            if buf.len() < 4 + UHID_DATA_MAX + 3 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short UHID output",
                ));
            }
            let size = (get_u16(buf, 4 + UHID_DATA_MAX) as usize).min(UHID_DATA_MAX);
            let mut data = &buf[4..4 + size];
            // The device has no numbered reports, so hidraw passes
            // the leading report number zero through to us.
            if data.len() == crate::ctaphid::PACKET_SIZE + 1 && data[0] == 0 {
                data = &data[1..];
            }
            OutputEvent::Output(data.to_vec())
        }
        UHID_GET_REPORT if buf.len() >= 8 => OutputEvent::GetReport {
            id: get_u32(buf, 4),
        },
        UHID_SET_REPORT if buf.len() >= 8 => OutputEvent::SetReport {
            id: get_u32(buf, 4),
        },
        other => OutputEvent::Unknown(other),
    };
    Ok(event)
}

/// A virtual HID device.
pub struct UHIDDevice {
    handle: AsyncFd<File>,
}

impl UHIDDevice {
    /// Create a device using the UHID character device at `path`.
    pub async fn create(params: &CreateParams, path: &Path) -> io::Result<UHIDDevice> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let mut device = UHIDDevice {
            handle: AsyncFd::new(file)?,
        };
        device.write_event(&encode_create(params)?).await?;
        Ok(device)
    }

    async fn write_event(&mut self, event: &[u8]) -> io::Result<()> {
        loop {
            let mut guard = self.handle.writable_mut().await?;
            match guard.try_io(|inner| inner.get_mut().write(event)) {
                Ok(Ok(n)) if n == event.len() => return Ok(()),
                Ok(Ok(_)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short write to UHID device",
                    ))
                }
                Ok(Err(err)) => return Err(err),
                Err(_would_block) => continue,
            }
        }
    }

    /// Wait for the next event from the kernel.  This is cancel safe.
    pub async fn read_event(&mut self) -> io::Result<OutputEvent> {
        let mut buf = vec![0u8; UHID_EVENT_SIZE];
        loop {
            let mut guard = self.handle.readable_mut().await?;
            match guard.try_io(|inner| inner.get_mut().read(&mut buf)) {
                Ok(Ok(n)) => return decode_output(&buf[..n]),
                Ok(Err(err)) => return Err(err),
                Err(_would_block) => continue,
            }
        }
    }

    /// Send an input report to the host.
    pub async fn send_input(&mut self, report: &[u8]) -> io::Result<()> {
        self.write_event(&encode_input(report)?).await
    }

    /// Wait for the next output report from the host, answering the
    /// other requests of the kernel along the way.
    pub async fn recv_output(&mut self) -> io::Result<Vec<u8>> {
        loop {
            match self.read_event().await? {
                OutputEvent::Output(data) => return Ok(data),
                OutputEvent::GetReport { id } => {
                    self.write_event(&encode_get_report_reply(id, libc::EIO as u16))
                        .await?
                }
                OutputEvent::SetReport { id } => {
                    self.write_event(&encode_set_report_reply(id, libc::EIO as u16))
                        .await?
                }
                other => log::debug!("UHID event {other:?}"),
            }
        }
    }
}

impl Drop for UHIDDevice {
    fn drop(&mut self) {
        // Closing the file descriptor destroys the device as well,
        // but be explicit about it.
        let _ = self.handle.get_mut().write(&UHID_DESTROY.to_ne_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_event_layout() {
        let params = CreateParams {
            name: "gkey".into(),
            phys: String::new(),
            uniq: String::new(),
            bus: BUS_USB,
            vendor: 1,
            product: 2,
            version: 3,
            country: 0,
            report_descriptor: vec![0xaa, 0xbb],
        };
        let ev = encode_create(&params).unwrap();
        assert_eq!(ev.len(), 4376);
        assert_eq!(get_u32(&ev, 0), UHID_CREATE2);
        assert_eq!(&ev[4..9], b"gkey\0");
        assert_eq!(get_u16(&ev, 260), 2);
        assert_eq!(get_u16(&ev, 262), BUS_USB);
        assert_eq!(get_u32(&ev, 264), 1);
        assert_eq!(&ev[280..282], &[0xaa, 0xbb]);
    }

    #[test]
    fn output_strips_report_number() {
        let mut ev = vec![0u8; UHID_EVENT_SIZE];
        ev[0..4].copy_from_slice(&UHID_OUTPUT.to_ne_bytes());
        ev[5] = 0x42;
        ev[4 + UHID_DATA_MAX..4 + UHID_DATA_MAX + 2].copy_from_slice(&65u16.to_ne_bytes());
        match decode_output(&ev).unwrap() {
            OutputEvent::Output(data) => {
                assert_eq!(data.len(), 64);
                assert_eq!(data[0], 0x42);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
