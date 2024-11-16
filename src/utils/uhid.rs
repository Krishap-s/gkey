use io::{Read, Write};
use std::borrow::BorrowMut;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use pin_project::pin_project;
use tio::unix::AsyncFd;
use tio::unix::TryIoError;
use tio::{AsyncRead, AsyncWrite};
use tokio::io as tio;

use uhid_virt::{CreateParams, InputEvent, StreamError, UHID_EVENT_SIZE};

pub enum UHIDErr {
    // Error trying to poll the file descriptor
    GuardErr(io::Error),
    //IO errors
    IOError(io::Error),
    // Parsing error into valid ['OutputEvent']
    StreamError(StreamError),
    // Tokio error when file descriptor will return an ['io::ErrorKind::WouldBlock'] error
    TryIOError(TryIoError),
}

// Taken from https://github.com/flukejones/uhid-virt/blob/master/src/uhid_device.rs and modified
// for tokio
#[pin_project]
pub struct UHIDDevice<T: Read + Write + AsRawFd> {
    pub handle: AsyncFd<T>,
}

/// Character misc-device handle for a specific HID device
impl<T: AsRawFd + Read + Write> UHIDDevice<T> {
    /// Write a SetReportReply, only use in reponse to a read SetReport event
    pub async fn write_set_report_reply(&mut self, id: u32, err: u16) -> Result<usize, UHIDErr> {
        let mut guard = self
            .handle
            .writable_mut()
            .await
            .map_err(UHIDErr::GuardErr)?;
        let event: [u8; UHID_EVENT_SIZE] = InputEvent::SetReportReply { id, err }.into();
        let write_res = guard
            .try_io(|handle| handle.get_mut().write(&event))
            .map_err(UHIDErr::TryIOError)?;
        write_res.map_err(UHIDErr::IOError)
    }

    /// Write a GetReportReply, only use in reponse to a read GetReport event
    pub async fn write_get_report_reply(
        &mut self,
        id: u32,
        err: u16,
        data: Vec<u8>,
    ) -> Result<usize, UHIDErr> {
        let mut guard = self
            .handle
            .writable_mut()
            .await
            .map_err(UHIDErr::GuardErr)?;
        let event: [u8; UHID_EVENT_SIZE] = InputEvent::GetReportReply { id, err, data }.into();
        let write_res = guard
            .try_io(|handle| handle.get_mut().write(&event))
            .map_err(UHIDErr::TryIOError)?;
        write_res.map_err(UHIDErr::IOError)
    }
}

//The try_io function of the asyncfd guard has to be looped to in the case a would block error may
//appear
impl<T: Read + Write + AsRawFd> AsyncRead for UHIDDevice<T> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tio::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        buf.set_filled(UHID_EVENT_SIZE);
        let device = self.project();
        let mut byte_data: [u8; UHID_EVENT_SIZE] = [0; UHID_EVENT_SIZE];
        device.handle.poll_read_ready_mut(cx).map(|guard_result| {
            guard_result.and_then(|mut guard| loop {
                match guard.try_io(|handle| handle.get_mut().read(byte_data.borrow_mut())) {
                    Ok(res) => break res.map(|_| ()),
                    Err(_) => continue,
                }
            })
        })
    }
}

impl<T: Read + Write + AsRawFd> AsyncWrite for UHIDDevice<T> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        let device = self.project();
        device.handle.poll_write_ready_mut(cx).map(|guard_result| {
            guard_result.and_then(|mut guard| loop {
                match guard.try_io(|handle| handle.get_mut().write(buf)) {
                    Ok(res) => break res,
                    Err(_) => continue,
                }
            })
        })
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        let device = self.project();
        device.handle.poll_write_ready_mut(cx).map(|guard_result| {
            guard_result.and_then(|mut guard| loop {
                match guard.try_io(|handle| handle.get_mut().flush()) {
                    Ok(res) => break res,
                    Err(_) => continue,
                }
            })
        })
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        let event: [u8; UHID_EVENT_SIZE] = InputEvent::Destroy.into();
        let device = self.project();
        device.handle.poll_write_ready_mut(cx).map(|guard_result| {
            guard_result.and_then(|mut guard| loop {
                match guard.try_io(|handle| handle.get_mut().write(&event)) {
                    Ok(res) => break res.map(|_| ()),
                    Err(_) => continue,
                }
            })
        })
    }
}

impl UHIDDevice<File> {
    /// Opens the character misc-device at /dev/uhid
    pub async fn create(params: CreateParams) -> io::Result<UHIDDevice<File>> {
        UHIDDevice::create_with_path(params, Path::new("/dev/uhid")).await
    }
    pub async fn create_with_path(
        params: CreateParams,
        path: &Path,
    ) -> io::Result<UHIDDevice<File>> {
        let mut options = OpenOptions::new();
        options.read(true);
        options.write(true);
        if cfg!(unix) {
            options.custom_flags(libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK);
        }
        let fd = options.open(path)?;

        let mut handle = AsyncFd::new(fd)?;
        let event: [u8; UHID_EVENT_SIZE] = InputEvent::Create(params).into();

        handle.writable_mut().await.and_then(|mut guard| loop {
            match guard.try_io(|handle| handle.get_mut().write(&event)) {
                Ok(res) => break res.map(|_| ()),
                Err(_) => continue,
            }
        })?;

        Ok(UHIDDevice { handle })
    }
}
