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

use std::ffi::CStr;
use std::path::PathBuf;
use std::process::ExitCode;

use gkey::getopt::{self, HasArg, Item, Opt};
use gkey::keystore::{self, hex, Keystore};
use gkey::tpm::{self, Tpm};
use gkey::PACKAGE_BUGREPORT;

const PROGRAM: &str = "gkey";

const OPTIONS: &[Opt] = &[
    Opt {
        long: "keystore",
        short: Some('k'),
        has_arg: HasArg::Required,
    },
    Opt {
        long: "tcti",
        short: Some('t'),
        has_arg: HasArg::Required,
    },
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
Manage the passkeys held by the TPM backed gkey authenticator.

Commands:
  list               list the stored credentials (the default)
  delete ID...       delete the credentials whose ID starts with ID
  info               describe the TPM and the keystore
  init               create an empty keystore

Options:
  -k, --keystore=DIR  use the keystore in DIR
                        (default: $XDG_DATA_HOME/gkey)
  -t, --tcti=CONF     reach the TPM through the TCTI CONF
                        (default: $GKEY_TCTI or {tcti})
      --help          display this help and exit
      --version       output version information and exit

Private keys never leave the TPM, so credentials cannot be exported.

Report bugs to: <{PACKAGE_BUGREPORT}>
",
        tcti = tpm::DEFAULT_TCTI
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

fn list(store: &Keystore) {
    if store.credentials.is_empty() {
        println!("No credentials.");
        return;
    }
    let mut rows = vec![[
        "ID".to_string(),
        "RELYING PARTY".to_string(),
        "USER".to_string(),
        "KIND".to_string(),
        "CREATED".to_string(),
        "USES".to_string(),
    ]];
    for c in &store.credentials {
        rows.push([
            c.id_hex(),
            c.rp_id.clone(),
            c.user_name
                .clone()
                .or_else(|| c.user_display_name.clone())
                .unwrap_or_else(|| "-".into()),
            if c.discoverable {
                "passkey"
            } else {
                "server-side"
            }
            .into(),
            date(c.created),
            c.sign_count.to_string(),
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

fn delete(tpm: &mut Tpm, store: &mut Keystore, prefixes: &[String]) -> Result<(), String> {
    if prefixes.is_empty() {
        return Err("missing credential ID".into());
    }
    let mut doomed = Vec::new();
    for prefix in prefixes {
        let found = store.find_prefix(prefix);
        match found.as_slice() {
            [] => return Err(format!("no credential matches '{prefix}'")),
            [index] => doomed.push(*index),
            _ => return Err(format!("'{prefix}' matches several credentials")),
        }
    }
    doomed.sort_unstable();
    doomed.dedup();
    for index in doomed.into_iter().rev() {
        let credential = store.credentials.remove(index);
        println!("deleted {} ({})", credential.id_hex(), credential.rp_id);
    }
    store.save(tpm).map_err(|e| e.to_string())
}

fn info(tpm: &mut Tpm, dir: &std::path::Path) -> Result<(), String> {
    println!("TPM manufacturer:     {}", tpm.vendor());
    println!("Storage key digest:   {}", hex(&tpm.fingerprint()));
    println!("Keystore:             {}", dir.display());
    if Keystore::exists(dir) {
        let store = Keystore::open(dir, tpm).map_err(|e| e.to_string())?;
        let passkeys = store.credentials.iter().filter(|c| c.discoverable).count();
        println!("Credentials:          {}", store.credentials.len());
        println!("  discoverable:       {passkeys}");
    } else {
        println!("Credentials:          none (no keystore)");
    }
    println!("AAGUID:               {}", hex(&gkey::ctap2::AAGUID));
    Ok(())
}

fn run(dir: PathBuf, tcti: String, command: &str, arguments: &[String]) -> Result<(), String> {
    if !matches!(command, "list" | "delete" | "info" | "init") {
        return Err(format!("unknown command '{command}'"));
    }
    if command != "delete" && !arguments.is_empty() {
        return Err(format!("extra operand '{}'", arguments[0]));
    }
    let mut tpm = Tpm::open(&tcti).map_err(|e| e.to_string())?;
    match command {
        "init" => {
            Keystore::create(&dir, &mut tpm).map_err(|e| e.to_string())?;
            println!("created keystore in {}", dir.display());
            Ok(())
        }
        "info" => info(&mut tpm, &dir),
        "list" => {
            let store = Keystore::open(&dir, &mut tpm).map_err(|e| e.to_string())?;
            list(&store);
            Ok(())
        }
        "delete" => {
            let mut store = Keystore::open(&dir, &mut tpm).map_err(|e| e.to_string())?;
            delete(&mut tpm, &mut store, arguments)
        }
        _ => unreachable!(),
    }
}

fn main() -> ExitCode {
    let items = match getopt::parse(std::env::args().skip(1), OPTIONS) {
        Ok(items) => items,
        Err(message) => return try_help(&message),
    };
    let mut dir: Option<PathBuf> = None;
    let mut tcti: Option<String> = None;
    let mut operands = Vec::new();
    for item in items {
        match item {
            Item::Opt("keystore", Some(value)) => dir = Some(value.into()),
            Item::Opt("tcti", Some(value)) => tcti = Some(value),
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
    let dir = match dir.map(Ok).unwrap_or_else(keystore::default_dir) {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("{PROGRAM}: {err}");
            return ExitCode::FAILURE;
        }
    };
    let tcti = tpm::tcti_from_environment(tcti.as_deref());
    let (command, arguments) = match operands.split_first() {
        Some((command, arguments)) => (command.as_str(), arguments),
        None => ("list", &[][..]),
    };
    match run(dir, tcti, command, arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message)
            if message.starts_with("unknown command")
                || message.starts_with("extra operand")
                || message.starts_with("missing") =>
        {
            try_help(&message)
        }
        Err(message) => {
            eprintln!("{PROGRAM}: {message}");
            ExitCode::FAILURE
        }
    }
}
