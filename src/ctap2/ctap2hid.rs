use crate::ctap2::channel::*;
use crate::prelude::*;
use std::{collections, pin, u32};

use passkey_transports::hid::{ChannelHandler, Command, Message};
use pin_project::pin_project;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::signal::unix;

/* Time to wait before exiting the program.
This is the graceful period for all existing sessions to finish */
const EXIT_TIMEOUT: u64 = 60 * 5;
/* Time to wait before shutting down listening sockets.
This is the graceful period for the new service to get ready */
const CLOSE_TIMEOUT: u64 = 5;

const PACKET_SIZE: usize = 64;

pub enum ShutdownType {
    Graceful,
    Quick,
}

#[pin_project]
pub struct CTAP2HID<T>
where
    T: AsyncReadExt + AsyncWriteExt,
{
    #[pin]
    hid: T,
    channel_manager: collections::BTreeMap<u32, Box<Channel<dyn ChannelState>>>,
    counter: u32,
}

impl<T> CTAP2HID<T>
where
    T: AsyncReadExt + AsyncWriteExt,
{
    pub fn new(hid: T) -> Self {
        let mut channel_pool = collections::BTreeSet::new();
        channel_pool.extend(0..u32::MAX);
        CTAP2HID {
            hid,
            channel_manager: collections::BTreeMap::new(),
            counter: 0,
        }
    }

    pub async fn shutdown_handler(self) -> ShutdownType {
        let mut graceful_terminate_signal = unix::signal(unix::SignalKind::terminate()).unwrap();
        let mut fast_shutdown_signal = unix::signal(unix::SignalKind::interrupt()).unwrap();
        tokio::select! {
            _ = fast_shutdown_signal.recv() => {
                ShutdownType::Quick
            },

            _ = graceful_terminate_signal.recv() => {
                ShutdownType::Graceful
            }
        }
    }

    pub async fn listen(mut self: pin::Pin<&mut Self>) -> Result<()> {
        let mut this = self.project();
        let mut channel_handler = ChannelHandler::default();
        let mut req_buf: [u8; PACKET_SIZE] = [0; PACKET_SIZE];
        let mut resp = Message::new(0, Command::Err, &[]).unwrap();
        loop {
            this.hid.read_buf(&mut &mut req_buf[..]).await?;
            if let Some(req) = channel_handler.handle_packet(&req_buf) {
                match (
                    req.command,
                    req.channel,
                    this.channel_manager.contains_key(&req.channel),
                ) {
                    // Create new channel
                    (Command::Init, u32::MAX, _) => {
                        while *this.counter == 0
                            || *this.counter == u32::MAX
                            || this.channel_manager.contains_key(this.counter)
                        {
                            (*this.counter, _) = this.counter.overflowing_add(1);
                        }
                        let channel = Box::new(Channel::<Free>::new(*this.counter));
                        this.channel_manager.insert(req.channel, channel).unwrap();
                        resp.channel = req.channel;
                        resp.command = Command::Init;
                        resp.payload.extend_from_slice(&req.payload);
                    }
                    // Reset channel
                    (Command::Init, _, true) => {}
                }
                resp.send(writer);
            }
        }
    }
}
