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

//! gkey: manage the credentials of the TPM backed authenticator.

use std::collections::HashMap;
use std::ffi::CStr;
use std::process::ExitCode;

use gkey::getopt::{self, HasArg, Item, Opt};
use gkey::manager::WireCredential;
use gkey::system::{INTERFACE, OBJECT_PATH, SERVICE_NAME};
use gkey::PACKAGE_BUGREPORT;
use zbus::{Connection, Proxy};

const PROGRAM: &str = "gkey";

const OPTIONS: &[Opt] = &[
    Opt {
        long: "help",
        short: None,
        has_arg: HasArg::No,
    },
    Opt {
        long: "version",
        short: None,
        has_arg: HasArg::No,
    },
];

fn usage() {
    print!(
        "\
Usage: {PROGRAM} [OPTION]... [COMMAND [ARGUMENT]...]
Manage your passkeys held by the TPM backed gkey authenticator.

Commands:
  list               list your credentials (the default)
  delete ID...       delete your credentials whose ID starts with ID
  info               describe the TPM and your keystore

Options:
      --help         display this help and exit
      --version      output version information and exit

{PROGRAM} talks to gkey-service over the system bus, which must be running.
Deleting credentials requires authentication.  Private keys never leave the
TPM, so credentials cannot be exported.

Report bugs to: <{PACKAGE_BUGREPORT}>
"
    );
}

fn try_help(message: &str) -> ExitCode {
    eprintln!("{PROGRAM}: {message}");
    eprintln!("Try '{PROGRAM} --help' for more information.");
    ExitCode::FAILURE
}

/// Format a time stamp as a local date.
fn date(seconds: u64) -> String {
    let time = seconds as libc::time_t;
    let mut buf = [0 as libc::c_char; 32];
    // SAFETY: localtime_r and strftime write into the given buffers.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&time, &mut tm).is_null() {
            return "-".into();
        }
        let n = libc::strftime(buf.as_mut_ptr(), buf.len(), c"%Y-%m-%d".as_ptr(), &tm);
        if n == 0 {
            return "-".into();
        }
        CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()
    }
}

fn print_table(credentials: &[WireCredential]) {
    let mut rows = vec![[
        "ID".to_string(),
        "RELYING PARTY".to_string(),
        "USER".to_string(),
        "KIND".to_string(),
        "CREATED".to_string(),
        "USES".to_string(),
    ]];
    for (id, rp_id, name, display_name, discoverable, created, uses) in credentials {
        let user = [name, display_name]
            .into_iter()
            .find(|s| !s.is_empty())
            .cloned()
            .unwrap_or_else(|| "-".into());
        rows.push([
            id.clone(),
            rp_id.clone(),
            user,
            if *discoverable {
                "passkey"
            } else {
                "server-side"
            }
            .into(),
            date(*created),
            uses.to_string(),
        ]);
    }
    let mut widths = [0usize; 6];
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    for row in &rows {
        let line: Vec<String> = row
            .iter()
            .zip(widths)
            .map(|(cell, width)| format!("{cell:width$}"))
            .collect();
        println!("{}", line.join("  ").trim_end());
    }
}

/// Turn a D-Bus error into a message for the user.
fn describe(err: zbus::Error) -> String {
    match err {
        zbus::Error::MethodError(name, message, _) => match name.as_str() {
            "org.freedesktop.DBus.Error.ServiceUnknown" => "gkey-service is not running".into(),
            "org.freedesktop.DBus.Error.AccessDenied" => "not authorized".into(),
            _ => message.unwrap_or_else(|| name.to_string()),
        },
        other => format!("D-Bus: {other}"),
    }
}

async fn run(command: &str, arguments: &[String]) -> Result<(), String> {
    let connection = Connection::system()
        .await
        .map_err(|e| format!("cannot connect to the system bus: {e}"))?;
    let proxy = Proxy::new(&connection, SERVICE_NAME, OBJECT_PATH, INTERFACE)
        .await
        .map_err(describe)?;
    match command {
        "list" => {
            let credentials: Vec<WireCredential> =
                proxy.call("ListCredentials", &()).await.map_err(describe)?;
            if credentials.is_empty() {
                println!("No credentials.");
            } else {
                print_table(&credentials);
            }
        }
        "delete" => {
            let deleted: Vec<WireCredential> = proxy
                .call("DeleteCredentials", &(arguments,))
                .await
                .map_err(describe)?;
            for (id, rp_id, ..) in deleted {
                println!("deleted {id} ({rp_id})");
            }
        }
        "info" => {
            let info: HashMap<String, String> = proxy.call("Info", &()).await.map_err(describe)?;
            let get = |key: &str| info.get(key).cloned().unwrap_or_else(|| "-".into());
            println!("Service version:      {}", get("version"));
            println!("TPM manufacturer:     {}", get("tpm-vendor"));
            println!("Storage key digest:   {}", get("storage-key-digest"));
            println!("Keystore:             {}", get("keystore"));
            println!("Credentials:          {}", get("credentials"));
            println!("  discoverable:       {}", get("discoverable"));
            println!("AAGUID:               {}", get("aaguid"));
        }
        _ => unreachable!("commands are checked by the caller"),
    }
    Ok(())
}

fn main() -> ExitCode {
    let items = match getopt::parse(std::env::args().skip(1), OPTIONS) {
        Ok(items) => items,
        Err(message) => return try_help(&message),
    };
    let mut operands = Vec::new();
    for item in items {
        match item {
            Item::Opt("help", None) => {
                usage();
                return ExitCode::SUCCESS;
            }
            Item::Opt("version", None) => {
                gkey::print_version(PROGRAM);
                return ExitCode::SUCCESS;
            }
            Item::Operand(operand) => operands.push(operand),
            Item::Opt(..) => unreachable!("option table and match disagree"),
        }
    }
    let (command, arguments) = match operands.split_first() {
        Some((command, arguments)) => (command.as_str(), arguments),
        None => ("list", &[][..]),
    };
    match command {
        "list" | "info" if !arguments.is_empty() => {
            return try_help(&format!("extra operand '{}'", arguments[0]))
        }
        "delete" if arguments.is_empty() => return try_help("missing credential ID"),
        "list" | "info" | "delete" => {}
        other => return try_help(&format!("unknown command '{other}'")),
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("{PROGRAM}: cannot start the event loop: {err}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(command, arguments)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{PROGRAM}: {message}");
            ExitCode::FAILURE
        }
    }
}
