use io::{Read, Write};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use tio::unix::AsyncFd;
use tio::unix::TryIoError;
use tokio::io as tio;

use uhid_virt::{CreateParams, InputEvent, OutputEvent, StreamError, UHID_EVENT_SIZE};

pub enum UHIDErr {
    //IO errors
    IOError(io::Error),
    // Parsing error into valid ['OutputEvent']
    StreamError(StreamError),
    // Tokio error when file descriptor will return an ['io::ErrorKind::WouldBlock'] error
    TryIOError(TryIoError),
}

// Taken from https://github.com/flukejones/uhid-virt/blob/master/src/uhid_device.rs and modified
// for tokio
pub struct UHIDDevice<T: AsRawFd + Read + Write> {
    handle: AsyncFd<T>,
}

/// Character misc-device handle for a specific HID device
impl<T: AsRawFd + Read + Write> UHIDDevice<T> {
    /// The data parameter should contain a data-payload. This is the raw data that you read from your device. The kernel will parse the HID reports.
    pub async fn write(&mut self, data: &[u8]) -> Result<io::Result<usize>, UHIDErr> {
        let mut gaurd = self.handle.writable_mut().await.map_err(UHIDErr::IOError)?;
        let event: [u8; UHID_EVENT_SIZE] = InputEvent::Input { data }.into();
        gaurd
            .try_io(|handle| handle.get_mut().write(&event))
            .map_err(UHIDErr::TryIOError)
    }

    /// Write a SetReportReply, only use in reponse to a read SetReport event
    pub async fn write_set_report_reply(
        &mut self,
        id: u32,
        err: u16,
    ) -> Result<io::Result<usize>, UHIDErr> {
        let mut gaurd = self.handle.writable_mut().await.map_err(UHIDErr::IOError)?;
        let event: [u8; UHID_EVENT_SIZE] = InputEvent::SetReportReply { id, err }.into();
        gaurd
            .try_io(|handle| handle.get_mut().write(&event))
            .map_err(UHIDErr::TryIOError)
    }

    /// Write a GetReportReply, only use in reponse to a read GetReport event
    pub async fn write_get_report_reply(
        &mut self,
        id: u32,
        err: u16,
        data: Vec<u8>,
    ) -> Result<io::Result<usize>, UHIDErr> {
        let mut gaurd = self.handle.writable_mut().await.map_err(UHIDErr::IOError)?;
        let event: [u8; UHID_EVENT_SIZE] = InputEvent::GetReportReply { id, err, data }.into();
        gaurd
            .try_io(|handle| handle.get_mut().write(&event))
            .map_err(UHIDErr::TryIOError)
    }

    /// Reads a queued output event. No reaction is required to an output event, but you should handle them according to your needs.
    pub async fn read(&mut self) -> Result<OutputEvent, UHIDErr> {
        let mut gaurd = self.handle.readable_mut().await.map_err(UHIDErr::IOError)?;
        let mut event = [0u8; UHID_EVENT_SIZE];
        let read_res = gaurd
            .try_io(|handle| handle.get_mut().read_exact(&mut event))
            .map_err(UHIDErr::TryIOError)?;
        // Propogate any errors returned by the read function
        match read_res {
            Ok(()) => OutputEvent::try_from(event).map_err(UHIDErr::StreamError),
            Err(e) => Err(UHIDErr::IOError(e)),
        }
    }

    /// This destroys the internal HID device. No further I/O will be accepted. There may still be pending output events that you can receive but no further input events can be sent to the kernel.
    pub async fn destroy(&mut self) -> Result<io::Result<usize>, UHIDErr> {
        let mut gaurd = self.handle.writable_mut().await.map_err(UHIDErr::IOError)?;
        let event: [u8; UHID_EVENT_SIZE] = InputEvent::Destroy.into();
        gaurd
            .try_io(|handle| handle.get_mut().write(&event))
            .map_err(UHIDErr::TryIOError)
    }
}

impl UHIDDevice<File> {
    /// Opens the character misc-device at /dev/uhid
    pub async fn create(params: CreateParams) -> Result<UHIDDevice<File>, UHIDErr> {
        UHIDDevice::create_with_path(params, Path::new("/dev/uhid")).await
    }
    pub async fn create_with_path(
        params: CreateParams,
        path: &Path,
    ) -> Result<UHIDDevice<File>, UHIDErr> {
        let mut options = OpenOptions::new();
        options.read(true);
        options.write(true);
        if cfg!(unix) {
            options.custom_flags(libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK);
        }
        let fd = options.open(path).map_err(UHIDErr::IOError)?;

        let mut handle = AsyncFd::new(fd).map_err(UHIDErr::IOError)?;
        let event: [u8; UHID_EVENT_SIZE] = InputEvent::Create(params).into();

        let mut gaurd = handle.writable_mut().await.map_err(UHIDErr::IOError)?;
        let write_res = gaurd
            .try_io(|handle| handle.get_mut().write_all(&event))
            .map_err(UHIDErr::TryIOError)?;
        // Propogate any errors returned by the write function
        match write_res {
            Ok(()) => Ok(UHIDDevice { handle }),
            Err(e) => Err(UHIDErr::IOError(e)),
        }
    }
}
