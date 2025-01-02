use crate::prelude;
use io::{Read, Write};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::task::{ready, Context, Poll};

use pin_project::pin_project;
use tio::unix::AsyncFd;
use tio::unix::TryIoError;
use tio::{AsyncRead, AsyncWrite};
use tokio::io as tio;

use uhid_virt::{CreateParams, InputEvent, OutputEvent, StreamError, UHID_EVENT_SIZE};

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

#[pin_project]
pub struct UHIDDevice<T: Read + Write + AsRawFd> {
    pub handle: AsyncFd<T>,
}

impl<T: Read + Write + AsRawFd> AsyncRead for UHIDDevice<T> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tio::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        loop {
            let mut guard = ready!(this.handle.poll_read_ready_mut(cx))?;

            let mut bytes = [0u8; UHID_EVENT_SIZE];
            match guard.try_io(|inner| inner.get_mut().read(&mut bytes)) {
                Ok(Ok(_)) => {
                    let event = OutputEvent::try_from(bytes)
                        .unwrap_or_else(|_| panic!("Invalid data from UHID FD"));
                    match event {
                        OutputEvent::Output { data } => buf.put_slice(&data),
                        _ => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Invalid event type from UHID",
                            )))
                        }
                    }
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl<T: Read + Write + AsRawFd> AsyncWrite for UHIDDevice<T> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        let this = self.project();
        let data: [u8; UHID_EVENT_SIZE] = InputEvent::Input { data: buf }.into();
        loop {
            let mut guard = ready!(this.handle.poll_read_ready_mut(cx))?;

            match guard.try_io(|inner| inner.get_mut().write(&data)) {
                Ok(Ok(size)) => return Poll::Ready(Ok(size)),
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        let this = self.project();
        loop {
            let mut guard = ready!(this.handle.poll_read_ready_mut(cx))?;

            match guard.try_io(|inner| inner.get_mut().flush()) {
                Ok(Ok(_)) => return Poll::Ready(Ok(())),
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        let this = self.project();
        let data: [u8; UHID_EVENT_SIZE] = InputEvent::Destroy.into();
        loop {
            let mut guard = ready!(this.handle.poll_read_ready_mut(cx))?;

            match guard.try_io(|inner| inner.get_mut().write(&data)) {
                Ok(Ok(_)) => return Poll::Ready(Ok(())),
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl UHIDDevice<File> {
    /// Opens the character misc-device at /dev/uhid
    pub async fn create(params: CreateParams) -> prelude::Result<UHIDDevice<File>> {
        UHIDDevice::create_with_path(params, Path::new("/dev/uhid")).await
    }
    pub async fn create_with_path(
        params: CreateParams,
        path: &Path,
    ) -> prelude::Result<UHIDDevice<File>> {
        let mut options = OpenOptions::new();
        options.read(true);
        options.write(true);
        if cfg!(unix) {
            options.custom_flags(libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK);
        }
        let fd = options.open(path)?;

        let mut handle = AsyncFd::new(fd)?;
        let event: [u8; UHID_EVENT_SIZE] = InputEvent::Create(params).into();
        loop {
            let mut guard = handle.writable_mut().await?;
            match guard.try_io(|inner| inner.get_mut().write(&event)) {
                Ok(Ok(_)) => return Ok(UHIDDevice { handle }),
                Ok(Err(err)) => return Err(prelude::Error::IO(err)),
                Err(_would_block) => continue,
            }
        }
    }
}
