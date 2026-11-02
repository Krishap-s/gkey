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

//! CTAPHID, the USB HID transport of the Client to Authenticator
//! Protocol (CTAP 2.0, section 8.1).
//!
//! The transport splits messages into 64 byte reports, multiplexes
//! logical channels over the device, and reports progress to the host
//! with keepalive messages while a request is waiting for the user.
//! CBOR requests are handed to an authenticator running on its own
//! thread, so that slow operations (TPM commands, user verification)
//! never stall the transport.

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

use crate::uhid::UHIDDevice;

/// Size of a HID report.
pub const PACKET_SIZE: usize = 64;
const INIT_DATA: usize = PACKET_SIZE - 7;
const CONT_DATA: usize = PACKET_SIZE - 5;
/// Largest message that fits into one initialization packet and 128
/// continuation packets.
pub const MAX_MESSAGE_SIZE: usize = INIT_DATA + 128 * CONT_DATA;

pub const BROADCAST_CID: u32 = 0xffff_ffff;

pub const CMD_PING: u8 = 0x01;
pub const CMD_MSG: u8 = 0x03;
pub const CMD_LOCK: u8 = 0x04;
pub const CMD_INIT: u8 = 0x06;
pub const CMD_WINK: u8 = 0x08;
pub const CMD_CBOR: u8 = 0x10;
pub const CMD_CANCEL: u8 = 0x11;
pub const CMD_KEEPALIVE: u8 = 0x3b;
pub const CMD_ERROR: u8 = 0x3f;

pub const ERR_INVALID_CMD: u8 = 0x01;
pub const ERR_INVALID_PAR: u8 = 0x02;
pub const ERR_INVALID_LEN: u8 = 0x03;
pub const ERR_INVALID_SEQ: u8 = 0x04;
pub const ERR_MSG_TIMEOUT: u8 = 0x05;
pub const ERR_CHANNEL_BUSY: u8 = 0x06;
pub const ERR_INVALID_CHANNEL: u8 = 0x0b;
pub const ERR_OTHER: u8 = 0x7f;

/// Keepalive status: the authenticator is processing the request.
pub const STATUS_PROCESSING: u8 = 1;
/// Keepalive status: the authenticator is waiting for the user.
pub const STATUS_UPNEEDED: u8 = 2;

const CAPABILITY_WINK: u8 = 0x01;
const CAPABILITY_CBOR: u8 = 0x04;
const CAPABILITY_NMSG: u8 = 0x08;

/// Time allowed between the packets of one message.
const TRANSACTION_TIMEOUT: Duration = Duration::from_millis(500);
const KEEPALIVE_INTERVAL: Duration = Duration::from_millis(100);
/// Number of allocated channels remembered at any one time.
const MAX_CHANNELS: usize = 256;

/// A source and sink of HID reports.
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// Receive the next output report.  Must be cancel safe.
    async fn recv(&mut self) -> io::Result<Vec<u8>>;
    /// Send an input report.
    async fn send(&mut self, packet: &[u8; PACKET_SIZE]) -> io::Result<()>;
}

impl Transport for UHIDDevice {
    async fn recv(&mut self) -> io::Result<Vec<u8>> {
        self.recv_output().await
    }

    async fn send(&mut self, packet: &[u8; PACKET_SIZE]) -> io::Result<()> {
        self.send_input(packet).await
    }
}

/// A CBOR request for the authenticator.
pub struct Request {
    /// The CTAP2 command byte followed by its CBOR parameters.
    pub payload: Vec<u8>,
    /// Set when the host cancels the request.
    pub cancel: Arc<AtomicBool>,
    /// Keepalive status reported to the host while processing.
    pub status: Arc<AtomicU8>,
    /// Where to send the response (status byte followed by CBOR).
    pub reply: oneshot::Sender<Vec<u8>>,
}

/// Split a message into packets.
pub fn fragment(cid: u32, cmd: u8, data: &[u8]) -> Vec<[u8; PACKET_SIZE]> {
    let mut packets = Vec::new();
    let mut packet = [0u8; PACKET_SIZE];
    packet[0..4].copy_from_slice(&cid.to_be_bytes());
    packet[4] = 0x80 | cmd;
    packet[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
    let first = data.len().min(INIT_DATA);
    packet[7..7 + first].copy_from_slice(&data[..first]);
    packets.push(packet);
    for (seq, chunk) in data[first..].chunks(CONT_DATA).enumerate() {
        let mut packet = [0u8; PACKET_SIZE];
        packet[0..4].copy_from_slice(&cid.to_be_bytes());
        packet[4] = seq as u8;
        packet[5..5 + chunk.len()].copy_from_slice(chunk);
        packets.push(packet);
    }
    packets
}

struct Assembly {
    cid: u32,
    cmd: u8,
    len: usize,
    data: Vec<u8>,
    seq: u8,
    last: Instant,
}

struct Busy {
    cid: u32,
    cancel: Arc<AtomicBool>,
    status: Arc<AtomicU8>,
    reply: oneshot::Receiver<Vec<u8>>,
    /// The channel was resynchronized; drop the reply.
    abandoned: bool,
}

/// The CTAPHID protocol engine.
pub struct Server<T: Transport> {
    transport: T,
    authenticator: mpsc::Sender<Request>,
    next_cid: u32,
    channels: VecDeque<u32>,
    assembly: Option<Assembly>,
    busy: Option<Busy>,
}

async fn wait_reply(busy: &mut Option<Busy>) -> Vec<u8> {
    match busy {
        Some(busy) => (&mut busy.reply)
            .await
            .unwrap_or_else(|_| vec![crate::ctap2::CTAP2_ERR_OTHER]),
        None => std::future::pending().await,
    }
}

impl<T: Transport> Server<T> {
    /// Create a server that forwards CBOR requests to `authenticator`.
    pub fn new(transport: T, authenticator: mpsc::Sender<Request>) -> Self {
        Server {
            transport,
            authenticator,
            next_cid: 1,
            channels: VecDeque::new(),
            assembly: None,
            busy: None,
        }
    }

    /// Serve requests until the transport fails.
    pub async fn run(&mut self) -> io::Result<()> {
        let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut was_busy = false;
        loop {
            let busy = self.busy.is_some();
            if busy && !was_busy {
                keepalive.reset();
            }
            was_busy = busy;
            tokio::select! {
                packet = self.transport.recv() => {
                    self.on_packet(&packet?).await?;
                }
                response = wait_reply(&mut self.busy) => {
                    if let Some(busy) = self.busy.take() {
                        if !busy.abandoned {
                            self.send(busy.cid, CMD_CBOR, &response).await?;
                        }
                    }
                }
                _ = keepalive.tick(), if busy => {
                    if let Some(busy) = &self.busy {
                        let (cid, status) = (busy.cid, busy.status.load(Ordering::Relaxed));
                        if !busy.abandoned {
                            self.send(cid, CMD_KEEPALIVE, &[status]).await?;
                        }
                    }
                }
            }
        }
    }

    async fn send(&mut self, cid: u32, cmd: u8, data: &[u8]) -> io::Result<()> {
        for packet in fragment(cid, cmd, data) {
            self.transport.send(&packet).await?;
        }
        Ok(())
    }

    async fn send_error(&mut self, cid: u32, code: u8) -> io::Result<()> {
        log::debug!("channel {cid:08x}: error {code:#04x}");
        self.send(cid, CMD_ERROR, &[code]).await
    }

    async fn on_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        if packet.len() < PACKET_SIZE {
            log::debug!("ignoring short report of {} bytes", packet.len());
            return Ok(());
        }
        let cid = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
        if cid == 0 {
            return self.send_error(cid, ERR_INVALID_CHANNEL).await;
        }

        // Expire a message whose sender stopped half way.
        if let Some(assembly) = &self.assembly {
            if assembly.last.elapsed() > TRANSACTION_TIMEOUT {
                let stale = assembly.cid;
                self.assembly = None;
                self.send_error(stale, ERR_MSG_TIMEOUT).await?;
            }
        }

        if packet[4] & 0x80 != 0 {
            let cmd = packet[4] & 0x7f;
            let len = u16::from_be_bytes([packet[5], packet[6]]) as usize;
            if let Some(assembly) = &self.assembly {
                if assembly.cid != cid {
                    return self.send_error(cid, ERR_CHANNEL_BUSY).await;
                }
                if cmd != CMD_INIT {
                    self.assembly = None;
                    return self.send_error(cid, ERR_INVALID_SEQ).await;
                }
                // An INIT aborts the message in progress.
                self.assembly = None;
            }
            if len > MAX_MESSAGE_SIZE {
                return self.send_error(cid, ERR_INVALID_LEN).await;
            }
            let first = len.min(INIT_DATA);
            if len <= INIT_DATA {
                return self.dispatch(cid, cmd, packet[7..7 + first].to_vec()).await;
            }
            let mut data = Vec::with_capacity(len);
            data.extend_from_slice(&packet[7..7 + first]);
            self.assembly = Some(Assembly {
                cid,
                cmd,
                len,
                data,
                seq: 0,
                last: Instant::now(),
            });
            return Ok(());
        }

        let seq = packet[4];
        let Some(assembly) = self.assembly.as_mut() else {
            // Spurious continuation packets are ignored.
            return Ok(());
        };
        if assembly.cid != cid {
            return Ok(());
        }
        if seq != assembly.seq {
            self.assembly = None;
            return self.send_error(cid, ERR_INVALID_SEQ).await;
        }
        let take = (assembly.len - assembly.data.len()).min(CONT_DATA);
        assembly.data.extend_from_slice(&packet[5..5 + take]);
        assembly.seq += 1;
        assembly.last = Instant::now();
        if assembly.data.len() == assembly.len {
            let assembly = self.assembly.take().expect("assembly in progress");
            return self.dispatch(cid, assembly.cmd, assembly.data).await;
        }
        Ok(())
    }

    fn allocate_channel(&mut self) -> u32 {
        loop {
            let cid = self.next_cid;
            self.next_cid = self.next_cid.wrapping_add(1);
            if cid != 0 && cid != BROADCAST_CID && !self.channels.contains(&cid) {
                if self.channels.len() == MAX_CHANNELS {
                    self.channels.pop_front();
                }
                self.channels.push_back(cid);
                return cid;
            }
        }
    }

    async fn dispatch(&mut self, cid: u32, cmd: u8, data: Vec<u8>) -> io::Result<()> {
        log::trace!(
            "channel {cid:08x}: command {cmd:#04x}, {} bytes",
            data.len()
        );
        if cmd == CMD_INIT {
            return self.init(cid, &data).await;
        }
        if cid == BROADCAST_CID || !self.channels.contains(&cid) {
            return self.send_error(cid, ERR_INVALID_CHANNEL).await;
        }
        if let Some(busy) = &self.busy {
            if busy.cid == cid && cmd == CMD_CANCEL {
                busy.cancel.store(true, Ordering::Relaxed);
                return Ok(());
            }
            return self.send_error(cid, ERR_CHANNEL_BUSY).await;
        }
        match cmd {
            CMD_PING => self.send(cid, CMD_PING, &data).await,
            CMD_WINK => self.send(cid, CMD_WINK, &[]).await,
            CMD_CANCEL => Ok(()),
            CMD_CBOR => {
                if data.is_empty() {
                    return self.send_error(cid, ERR_INVALID_LEN).await;
                }
                let (reply, receiver) = oneshot::channel();
                let busy = Busy {
                    cid,
                    cancel: Arc::new(AtomicBool::new(false)),
                    status: Arc::new(AtomicU8::new(STATUS_PROCESSING)),
                    reply: receiver,
                    abandoned: false,
                };
                let request = Request {
                    payload: data,
                    cancel: busy.cancel.clone(),
                    status: busy.status.clone(),
                    reply,
                };
                if self.authenticator.send(request).is_err() {
                    return self.send_error(cid, ERR_OTHER).await;
                }
                self.busy = Some(busy);
                Ok(())
            }
            CMD_MSG | CMD_LOCK => self.send_error(cid, ERR_INVALID_CMD).await,
            _ => self.send_error(cid, ERR_INVALID_CMD).await,
        }
    }

    async fn init(&mut self, cid: u32, nonce: &[u8]) -> io::Result<()> {
        if nonce.len() != 8 {
            return self.send_error(cid, ERR_INVALID_LEN).await;
        }
        let new_cid = if cid == BROADCAST_CID {
            self.allocate_channel()
        } else {
            if !self.channels.contains(&cid) {
                return self.send_error(cid, ERR_INVALID_CHANNEL).await;
            }
            // Resynchronize: abandon whatever the channel was doing.
            if let Some(busy) = self.busy.as_mut().filter(|busy| busy.cid == cid) {
                busy.cancel.store(true, Ordering::Relaxed);
                busy.abandoned = true;
            }
            cid
        };
        let version: Vec<u8> = crate::VERSION
            .split('.')
            .map(|part| part.parse().unwrap_or(0))
            .chain(std::iter::repeat(0))
            .take(3)
            .collect();
        let mut response = Vec::with_capacity(17);
        response.extend_from_slice(nonce);
        response.extend_from_slice(&new_cid.to_be_bytes());
        response.push(2); // CTAPHID protocol version
        response.extend_from_slice(&version);
        response.push(CAPABILITY_WINK | CAPABILITY_CBOR | CAPABILITY_NMSG);
        self.send(cid, CMD_INIT, &response).await
    }
}

impl<T: Transport> Drop for Server<T> {
    fn drop(&mut self) {
        // Do not leave the authenticator waiting for the user.
        if let Some(busy) = &self.busy {
            busy.cancel.store(true, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc as tmpsc;

    struct Pipe {
        rx: tmpsc::UnboundedReceiver<Vec<u8>>,
        tx: tmpsc::UnboundedSender<[u8; PACKET_SIZE]>,
    }

    impl Transport for Pipe {
        async fn recv(&mut self) -> io::Result<Vec<u8>> {
            self.rx
                .recv()
                .await
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }

        async fn send(&mut self, packet: &[u8; PACKET_SIZE]) -> io::Result<()> {
            self.tx
                .send(*packet)
                .map_err(|_| io::ErrorKind::BrokenPipe.into())
        }
    }

    struct Host {
        tx: tmpsc::UnboundedSender<Vec<u8>>,
        rx: tmpsc::UnboundedReceiver<[u8; PACKET_SIZE]>,
    }

    impl Host {
        fn send(&self, cid: u32, cmd: u8, data: &[u8]) {
            for packet in fragment(cid, cmd, data) {
                self.tx.send(packet.to_vec()).unwrap();
            }
        }

        async fn recv(&mut self) -> (u32, u8, Vec<u8>) {
            let first = self.rx.recv().await.unwrap();
            let cid = u32::from_be_bytes(first[0..4].try_into().unwrap());
            let cmd = first[4] & 0x7f;
            let len = u16::from_be_bytes([first[5], first[6]]) as usize;
            let mut data = first[7..7 + len.min(INIT_DATA)].to_vec();
            while data.len() < len {
                let next = self.rx.recv().await.unwrap();
                let take = (len - data.len()).min(CONT_DATA);
                data.extend_from_slice(&next[5..5 + take]);
            }
            (cid, cmd, data)
        }
    }

    fn start() -> (Host, mpsc::Receiver<Request>) {
        let (host_tx, dev_rx) = tmpsc::unbounded_channel();
        let (dev_tx, host_rx) = tmpsc::unbounded_channel();
        let (auth_tx, auth_rx) = mpsc::channel();
        let mut server = Server::new(
            Pipe {
                rx: dev_rx,
                tx: dev_tx,
            },
            auth_tx,
        );
        tokio::spawn(async move {
            let _ = server.run().await;
        });
        (
            Host {
                tx: host_tx,
                rx: host_rx,
            },
            auth_rx,
        )
    }

    async fn open_channel(host: &mut Host) -> u32 {
        host.send(BROADCAST_CID, CMD_INIT, b"12345678");
        let (cid, cmd, data) = host.recv().await;
        assert_eq!((cid, cmd), (BROADCAST_CID, CMD_INIT));
        assert_eq!(&data[..8], b"12345678");
        assert_eq!(data[16] & CAPABILITY_CBOR, CAPABILITY_CBOR);
        u32::from_be_bytes(data[8..12].try_into().unwrap())
    }

    #[tokio::test]
    async fn init_and_long_ping() {
        let (mut host, _auth) = start();
        let cid = open_channel(&mut host).await;
        assert_ne!(cid, BROADCAST_CID);
        let message: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        host.send(cid, CMD_PING, &message);
        assert_eq!(host.recv().await, (cid, CMD_PING, message));
    }

    #[tokio::test]
    async fn rejects_unknown_channel() {
        let (mut host, _auth) = start();
        host.send(0x1234_5678, CMD_PING, b"x");
        assert_eq!(
            host.recv().await,
            (0x1234_5678, CMD_ERROR, vec![ERR_INVALID_CHANNEL])
        );
    }

    #[tokio::test]
    async fn cbor_with_keepalive_and_cancel() {
        let (mut host, auth) = start();
        let cid = open_channel(&mut host).await;
        host.send(cid, CMD_CBOR, &[0x04]);
        let request = tokio::task::spawn_blocking(move || auth.recv().unwrap())
            .await
            .unwrap();
        assert_eq!(request.payload, vec![0x04]);
        request.status.store(STATUS_UPNEEDED, Ordering::Relaxed);
        let (_, cmd, data) = host.recv().await;
        assert_eq!(cmd, CMD_KEEPALIVE);
        assert!(data == [STATUS_PROCESSING] || data == [STATUS_UPNEEDED]);
        // Other channels are told to wait.
        let other = open_channel(&mut host).await;
        host.send(other, CMD_PING, b"x");
        loop {
            let (c, cmd, data) = host.recv().await;
            if c == other {
                assert_eq!((cmd, data), (CMD_ERROR, vec![ERR_CHANNEL_BUSY]));
                break;
            }
        }
        host.send(cid, CMD_CANCEL, &[]);
        while !request.cancel.load(Ordering::Relaxed) {
            tokio::task::yield_now().await;
        }
        request.reply.send(vec![0x2d]).unwrap();
        loop {
            let (c, cmd, data) = host.recv().await;
            if cmd != CMD_KEEPALIVE {
                assert_eq!((c, cmd, data), (cid, CMD_CBOR, vec![0x2d]));
                break;
            }
        }
    }
}
