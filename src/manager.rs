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

//! The management interface of gkey-service on the system bus.
//!
//! Users manage their own passkeys through it, with the `gkey`
//! program.  The service identifies callers by the user ID the bus
//! reports for them, so a user can only ever see and change their own
//! credentials, and deleting credentials requires polkit
//! authorization.
//!
//! Methods of `io.github.krishap_s.Gkey1`:
//!
//! * `ListCredentials() -> a(ssssbtu)`: ID, relying party, user name,
//!   display name, whether discoverable, creation time and use count
//!   of each credential of the caller.
//! * `DeleteCredentials(as ids) -> a(ssssbtu)`: delete the caller's
//!   credentials whose IDs start with each element of `ids`, and
//!   return them.
//! * `Info() -> a{ss}`: describe the TPM and the caller's keystore.

use std::collections::HashMap;

use tokio::sync::oneshot;
use zbus::message::Header;
use zbus::{fdo, interface};

use crate::ctap2::{CredentialSummary, Jobs, Manage};
use crate::system::{Subject, SystemBus, ACTION_MANAGE};

/// A credential as transmitted over D-Bus.
pub type WireCredential = (String, String, String, String, bool, u64, u32);

fn wire(c: CredentialSummary) -> WireCredential {
    (
        c.id,
        c.rp_id,
        c.user_name,
        c.user_display_name,
        c.discoverable,
        c.created,
        c.sign_count,
    )
}

/// The object served at [`crate::system::OBJECT_PATH`].
pub struct Manager {
    pub bus: SystemBus,
    pub jobs: Jobs,
}

fn failed(message: impl std::fmt::Display) -> fdo::Error {
    fdo::Error::Failed(message.to_string())
}

impl Manager {
    async fn caller(&self, header: &Header<'_>) -> fdo::Result<(String, u32)> {
        let sender = header
            .sender()
            .ok_or_else(|| failed("message without sender"))?
            .to_string();
        let uid = self.bus.caller_uid(&sender).await.map_err(failed)?;
        Ok((sender, uid))
    }

    async fn run<T>(
        &self,
        request: impl FnOnce(oneshot::Sender<Result<T, String>>) -> Manage,
    ) -> fdo::Result<T> {
        let (reply, receiver) = oneshot::channel();
        if !self.jobs.manage(request(reply)) {
            return Err(failed("the authenticator has stopped"));
        }
        receiver
            .await
            .map_err(|_| failed("the authenticator has stopped"))?
            .map_err(failed)
    }
}

#[interface(name = "io.github.krishap_s.Gkey1")]
impl Manager {
    async fn list_credentials(
        &self,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<Vec<WireCredential>> {
        let (_, uid) = self.caller(&header).await?;
        let list = self.run(|reply| Manage::List { uid, reply }).await?;
        Ok(list.into_iter().map(wire).collect())
    }

    async fn delete_credentials(
        &self,
        #[zbus(header)] header: Header<'_>,
        ids: Vec<String>,
    ) -> fdo::Result<Vec<WireCredential>> {
        if ids.is_empty() {
            return Err(fdo::Error::InvalidArgs("no credential IDs".into()));
        }
        let (sender, uid) = self.caller(&header).await?;
        let message = format!(
            "Delete {} passkey{} stored in gkey?",
            ids.len(),
            if ids.len() == 1 { "" } else { "s" }
        );
        let cancellation_id = format!("gkey-manage-{sender}");
        let authorized = self
            .bus
            .check_authorization_async(
                &Subject::BusName(sender),
                ACTION_MANAGE,
                &message,
                &cancellation_id,
            )
            .await
            .map_err(failed)?;
        if !authorized {
            return Err(fdo::Error::AccessDenied("not authorized".into()));
        }
        let deleted = self.run(|reply| Manage::Delete { uid, ids, reply }).await?;
        Ok(deleted.into_iter().map(wire).collect())
    }

    async fn info(
        &self,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<HashMap<String, String>> {
        let (_, uid) = self.caller(&header).await?;
        let info = self.run(|reply| Manage::Info { uid, reply }).await?;
        let mut out = HashMap::new();
        out.insert("tpm-vendor".into(), info.vendor);
        out.insert("storage-key-digest".into(), info.fingerprint);
        out.insert("keystore".into(), info.keystore.display().to_string());
        out.insert("credentials".into(), info.credentials.to_string());
        out.insert("discoverable".into(), info.discoverable.to_string());
        out.insert("aaguid".into(), crate::keystore::hex(&crate::ctap2::AAGUID));
        out.insert("version".into(), crate::VERSION.into());
        Ok(out)
    }
}
