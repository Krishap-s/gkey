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

//! gkey-service: present the TPM backed authenticator to the system
//! as a USB HID FIDO2 security key.

use std::io::Write;
use std::os::unix::fs::FileTypeExt;
use std::path::PathBuf;
use std::process::ExitCode;

use gkey::ctaphid::Server;
use gkey::getopt::{self, HasArg, Item, Opt};
use gkey::polkit::Polkit;
use gkey::privilege;
use gkey::uhid::{CreateParams, UHIDDevice, BUS_USB, UHID_PATH};
use gkey::verify::{Method, Verifier};
use gkey::{ctap2, keystore, tpm, PACKAGE_BUGREPORT};

const PROGRAM: &str = "gkey-service";

/// HID report descriptor of a FIDO authenticator, from the FIDO
/// CTAP 2.0 specification, section 8.1.8.2.
const REPORT_DESCRIPTOR: [u8; 34] = [
    0x06, 0xd0, 0xf1, // Usage Page (FIDO Alliance, 0xF1D0)
    0x09, 0x01, //       Usage (CTAPHID, 0x01)
    0xa1, 0x01, //       Collection (Application)
    0x09, 0x20, //         Usage (Input Report Data, 0x20)
    0x15, 0x00, //         Logical Minimum (0)
    0x26, 0xff, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x81, 0x02, //         Input (Data, Variable, Absolute)
    0x09, 0x21, //         Usage (Output Report Data, 0x21)
    0x15, 0x00, //         Logical Minimum (0)
    0x26, 0xff, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x91, 0x02, //         Output (Data, Variable, Absolute)
    0xc0, //             End Collection
];

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
        long: "uhid",
        short: None,
        has_arg: HasArg::Required,
    },
    Opt {
        long: "verify",
        short: None,
        has_arg: HasArg::Required,
    },
    Opt {
        long: "verify-command",
        short: None,
        has_arg: HasArg::Required,
    },
    Opt {
        long: "verbose",
        short: Some('v'),
        has_arg: HasArg::No,
    },
    Opt {
        long: "quiet",
        short: Some('q'),
        has_arg: HasArg::No,
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
Usage: {PROGRAM} [OPTION]...
Act as a FIDO2 security key whose credentials are protected by the TPM.

The service creates a virtual USB HID authenticator through UHID and
answers the requests that web browsers and other FIDO clients send to it.

  -k, --keystore=DIR        keep credentials in DIR
                              (default: $XDG_DATA_HOME/gkey)
  -t, --tcti=CONF           reach the TPM through the TCTI CONF
                              (default: $GKEY_TCTI or {tcti})
      --uhid=FILE           create the device through FILE
                              (default: {UHID_PATH})
      --verify=METHOD       ask for user consent with METHOD: 'polkit' (the
                              default) or 'command'
      --verify-command=CMD  run CMD to ask for consent; implies
                              --verify=command
  -v, --verbose             also print debugging messages; repeat to trace
                              every HID message
  -q, --quiet               print only error messages
      --help                display this help and exit
      --version             output version information and exit

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

fn init_logging(verbosity: i32) {
    // By default each request and its outcome are logged: the service
    // runs unattended, and its journal is where its behaviour is told.
    let level = match verbosity {
        i32::MIN..=-1 => log::LevelFilter::Error,
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    // The TPM library is chatty at the information level (it reports
    // closing its context); its warnings are enough until debugging.
    let library = if verbosity >= 1 {
        level
    } else {
        log::LevelFilter::Warn.min(level)
    };
    env_logger::Builder::new()
        .filter_level(level)
        .filter_module("tss_esapi", library)
        .parse_env("GKEY_LOG")
        .format(|buf, record| {
            let prefix = match record.level() {
                log::Level::Warn => "warning: ",
                _ => "",
            };
            writeln!(buf, "{PROGRAM}: {prefix}{}", record.args())
        })
        .init();
}

fn main() -> ExitCode {
    // Anyone may run this set-user-ID program with any environment, so
    // forget the variables that could redirect it before anything reads
    // them or starts a thread.
    let privileged = privilege::is_privileged();
    if privileged {
        privilege::sanitize_environment();
    }
    let items = match getopt::parse(std::env::args().skip(1), OPTIONS) {
        Ok(items) => items,
        Err(message) => return try_help(&message),
    };
    let mut keystore_dir: Option<PathBuf> = None;
    let mut tcti: Option<String> = None;
    let mut uhid = PathBuf::from(UHID_PATH);
    let mut method = String::from("polkit");
    let mut command: Option<String> = None;
    let mut verbosity = 0;
    for item in items {
        match item {
            Item::Opt("keystore", Some(dir)) => keystore_dir = Some(dir.into()),
            Item::Opt("tcti", Some(value)) => tcti = Some(value),
            Item::Opt("uhid", Some(path)) => uhid = path.into(),
            Item::Opt("verify", Some(value)) => method = value,
            Item::Opt("verify-command", Some(value)) => {
                method = "command".into();
                command = Some(value);
            }
            Item::Opt("verbose", None) => verbosity += 1,
            Item::Opt("quiet", None) => verbosity = -1,
            Item::Opt("help", None) => {
                usage();
                return ExitCode::SUCCESS;
            }
            Item::Opt("version", None) => {
                gkey::print_version(PROGRAM);
                return ExitCode::SUCCESS;
            }
            Item::Operand(operand) => return try_help(&format!("extra operand '{operand}'")),
            Item::Opt(..) => unreachable!("option table and match disagree"),
        }
    }
    init_logging(verbosity);

    if privileged {
        // These would let the caller pick another TPM library, device
        // or consent method while the program runs as gkey.
        let refused = [
            ("--tcti", tcti.is_some()),
            ("--uhid", uhid.as_path() != std::path::Path::new(UHID_PATH)),
            ("--verify=command", method == "command"),
        ];
        if let Some((option, _)) = refused.iter().find(|(_, given)| *given) {
            return try_help(&format!(
                "option '{option}' is not allowed when {PROGRAM} runs set-user-ID {}",
                privilege::GKEY_USER
            ));
        }
        if let Some(warning) = privilege::membership_warning() {
            log::warn!("{warning}");
        }
    }

    let command = match (method.as_str(), command) {
        ("polkit", _) => None,
        ("command", Some(command)) => Some(command),
        ("command", None) => return try_help("--verify=command requires --verify-command"),
        (other, _) => return try_help(&format!("invalid verification method '{other}'")),
    };
    let keystore_dir = match keystore_dir.map(Ok).unwrap_or_else(keystore::default_dir) {
        Ok(dir) => dir,
        Err(err) => {
            log::error!("{err}");
            return ExitCode::FAILURE;
        }
    };
    log::info!(
        "{PROGRAM} {} starting{}",
        gkey::VERSION,
        if privileged { ", set-user-ID" } else { "" }
    );
    log::info!("keystore: {}", keystore_dir.display());
    log::info!(
        "user consent: {}",
        match &command {
            Some(command) => format!("command '{command}'"),
            None => "polkit".to_string(),
        }
    );
    let tcti = if privileged {
        tpm::DEFAULT_TCTI.to_string()
    } else {
        tpm::tcti_from_environment(tcti.as_deref())
    };

    // The authenticator thread waits for polkit's answers while the
    // event loop runs, which needs a multi-threaded runtime.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            log::error!("cannot start the event loop: {err}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(serve(tcti, keystore_dir, uhid, command, privileged)) {
        Ok(()) => {
            log::info!("exiting");
            ExitCode::SUCCESS
        }
        Err(message) => {
            log::error!("{message}");
            ExitCode::FAILURE
        }
    }
}

async fn serve(
    tcti: String,
    keystore_dir: PathBuf,
    uhid: PathBuf,
    command: Option<String>,
    privileged: bool,
) -> Result<(), String> {
    let method = match command {
        Some(command) => Method::Command(command),
        None => Method::Polkit(Polkit::connect().await.map_err(|e| e.to_string())?),
    };
    let authenticator =
        ctap2::spawn(tcti, keystore_dir, Verifier { method }).map_err(|e| e.to_string())?;
    let result = async {
        let params = CreateParams {
            name: "gkey TPM authenticator".into(),
            phys: String::new(),
            uniq: String::new(),
            bus: BUS_USB,
            vendor: 0,
            product: 0,
            version: 1,
            country: 0,
            report_descriptor: REPORT_DESCRIPTOR.to_vec(),
        };
        if privileged {
            let metadata =
                std::fs::metadata(&uhid).map_err(|e| format!("{}: {e}", uhid.display()))?;
            if !metadata.file_type().is_char_device() {
                return Err(format!("{} is not a character device", uhid.display()));
            }
        }
        let device = UHIDDevice::create(&params, &uhid)
            .await
            .map_err(|e| format!("{}: {e}", uhid.display()))?;
        // The TPM, the UHID device and the bus are open: give up the gkey
        // account before touching any file, in particular the keystore.
        if privileged {
            privilege::drop_privileges().map_err(|e| e.to_string())?;
        }
        log::info!(
            "authenticator ready: virtual security key created through {}",
            uhid.display()
        );
        let mut server = Server::new(device, authenticator.sender());
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|e| e.to_string())?;
        tokio::select! {
            result = server.run() => result.map_err(|e| format!("HID transport: {e}")),
            _ = tokio::signal::ctrl_c() => Ok(()),
            _ = terminate.recv() => Ok(()),
        }
    }
    .await;
    // Withdrawing a pending polkit request needs the event loop, so
    // wait for the authenticator from a blocking task.
    let _ = tokio::task::spawn_blocking(move || authenticator.shutdown()).await;
    result
}
