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

//! Serve the authenticator over a Unix domain socket instead of UHID,
//! one 64 byte HID report per read or write.  This lets FIDO client
//! libraries exercise gkey on systems without /dev/uhid, and is used
//! by the test suite.  User consent is always granted.
//!
//! Usage: socket-authenticator SOCKET KEYSTORE-DIR

use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{signal, SignalKind};

use gkey::ctaphid::{Server, Transport, PACKET_SIZE};
use gkey::verify::{Method, Verifier};

struct Socket(UnixStream);

impl Transport for Socket {
    async fn recv(&mut self) -> io::Result<Vec<u8>> {
        let mut packet = vec![0u8; PACKET_SIZE];
        self.0.read_exact(&mut packet).await?;
        Ok(packet)
    }

    async fn send(&mut self, packet: &[u8; PACKET_SIZE]) -> io::Result<()> {
        self.0.write_all(packet).await
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} SOCKET KEYSTORE-DIR", args[0]);
        std::process::exit(1);
    }
    let _ = std::fs::remove_file(&args[1]);
    let listener = UnixListener::bind(&args[1])?;
    let authenticator = gkey::ctap2::spawn(
        gkey::tpm::tcti_from_environment(None),
        args[2].clone().into(),
        Verifier {
            method: Method::Command("true".into()),
        },
    )?;
    let mut terminate = signal(SignalKind::terminate())?;
    let serve = async {
        loop {
            let (stream, _) = listener.accept().await?;
            let mut server = Server::new(Socket(stream), authenticator.sender());
            if let Err(err) = server.run().await {
                if err.kind() != io::ErrorKind::UnexpectedEof {
                    return Err::<(), io::Error>(err);
                }
            }
        }
    };
    let result = tokio::select! {
        result = serve => result,
        _ = terminate.recv() => Ok(()),
        _ = tokio::signal::ctrl_c() => Ok(()),
    };
    // Flush the TPM objects, which matters for TPMs used without a
    // resource manager such as swtpm.
    authenticator.shutdown();
    let _ = std::fs::remove_file(&args[1]);
    Ok(result?)
}
