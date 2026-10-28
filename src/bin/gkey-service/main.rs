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
use std::path::PathBuf;
use std::process::ExitCode;

use gkey::ctaphid::Server;
use gkey::getopt::{self, HasArg, Item, Opt};
use gkey::manager::Manager;
use gkey::system::{SystemBus, UserSource, OBJECT_PATH, SERVICE_NAME};
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
        long: "state-dir",
        short: Some('s'),
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
        long: "seat",
        short: None,
        has_arg: HasArg::Required,
    },
    Opt {
        long: "user",
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
answers the requests that web browsers and other FIDO clients send to it,
on behalf of the user of the active session on the seat.  It is meant to
run as a system service under a dedicated account.

  -s, --state-dir=DIR       keep the keystores of the users in DIR
                              (default: $STATE_DIRECTORY or {state})
  -t, --tcti=CONF           reach the TPM through the TCTI CONF
                              (default: $GKEY_TCTI or {tcti})
      --uhid=FILE           create the device through FILE
                              (default: {UHID_PATH})
      --seat=SEAT           serve the active user of SEAT (default: seat0)
      --user=UID            serve the user UID instead, without consulting
                              logind; meant for testing
      --verify=METHOD       ask for user consent with METHOD: 'polkit' (the
                              default) or 'command'
      --verify-command=CMD  run CMD to ask for consent; implies
                              --verify=command
  -v, --verbose             print more messages; repeat for even more
  -q, --quiet               print only error messages
      --help                display this help and exit
      --version             output version information and exit

Report bugs to: <{PACKAGE_BUGREPORT}>
",
        state = keystore::DEFAULT_STATE_DIR,
        tcti = tpm::DEFAULT_TCTI
    );
}

fn try_help(message: &str) -> ExitCode {
    eprintln!("{PROGRAM}: {message}");
    eprintln!("Try '{PROGRAM} --help' for more information.");
    ExitCode::FAILURE
}

fn init_logging(verbosity: i32) {
    let level = match verbosity {
        i32::MIN..=-1 => log::LevelFilter::Error,
        0 => log::LevelFilter::Warn,
        1 => log::LevelFilter::Info,
        2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    env_logger::Builder::new()
        .filter_level(level)
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

/// Settings gathered from the command line.
struct Settings {
    state_dir: PathBuf,
    tcti: String,
    uhid: PathBuf,
    seat: String,
    user: Option<u32>,
    command: Option<String>,
}

async fn serve(settings: Settings) -> Result<(), String> {
    // The system bus is needed to find the user (logind), to ask for
    // consent (polkit), and to offer the management interface.
    let needs_bus = settings.user.is_none() || settings.command.is_none();
    let bus = if needs_bus {
        Some(SystemBus::connect().await.map_err(|e| e.to_string())?)
    } else {
        None
    };
    let users = match (settings.user, &bus) {
        (Some(uid), _) => UserSource::Fixed(uid),
        (None, Some(bus)) => UserSource::Seat {
            bus: bus.clone(),
            seat: settings.seat.clone(),
        },
        (None, None) => unreachable!("the bus is connected when needed"),
    };
    let method = match (&settings.command, &bus) {
        (Some(command), _) => Method::Command(command.clone()),
        (None, Some(bus)) => Method::Polkit(bus.clone()),
        (None, None) => unreachable!("the bus is connected when needed"),
    };
    let authenticator = ctap2::spawn(
        settings.tcti,
        &settings.state_dir,
        users,
        Verifier { method },
    )
    .map_err(|e| e.to_string())?;

    let result = async {
        if let Some(bus) = &bus {
            let manager = Manager {
                bus: bus.clone(),
                jobs: authenticator.sender(),
            };
            let connection = bus.connection();
            connection
                .object_server()
                .at(OBJECT_PATH, manager)
                .await
                .map_err(|e| format!("D-Bus: {e}"))?;
            connection
                .request_name(SERVICE_NAME)
                .await
                .map_err(|e| format!("cannot own {SERVICE_NAME} on the system bus: {e}"))?;
        } else {
            log::info!("not using the system bus; the management interface is disabled");
        }

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
        let device = UHIDDevice::create(&params, &settings.uhid)
            .await
            .map_err(|e| format!("{}: {e}", settings.uhid.display()))?;
        log::info!("authenticator ready");
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

    // Drop every queue to the authenticator so that its thread ends
    // and releases the TPM.  The management object holds one.
    if let Some(bus) = &bus {
        let _ = bus
            .connection()
            .object_server()
            .remove::<Manager, _>(OBJECT_PATH)
            .await;
    }
    let _ = tokio::task::spawn_blocking(move || authenticator.shutdown()).await;
    result
}

fn main() -> ExitCode {
    let items = match getopt::parse(std::env::args().skip(1), OPTIONS) {
        Ok(items) => items,
        Err(message) => return try_help(&message),
    };
    let mut state_dir: Option<PathBuf> = None;
    let mut tcti: Option<String> = None;
    let mut uhid = PathBuf::from(UHID_PATH);
    let mut seat = String::from("seat0");
    let mut user: Option<u32> = None;
    let mut method = String::from("polkit");
    let mut command: Option<String> = None;
    let mut verbosity = 0;
    for item in items {
        match item {
            Item::Opt("state-dir", Some(dir)) => state_dir = Some(dir.into()),
            Item::Opt("tcti", Some(value)) => tcti = Some(value),
            Item::Opt("uhid", Some(path)) => uhid = path.into(),
            Item::Opt("seat", Some(value)) => seat = value,
            Item::Opt("user", Some(value)) => match value.parse() {
                Ok(uid) => user = Some(uid),
                Err(_) => return try_help(&format!("invalid user ID '{value}'")),
            },
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

    let command = match (method.as_str(), command) {
        ("polkit", _) => None,
        ("command", Some(command)) => Some(command),
        ("command", None) => return try_help("--verify=command requires --verify-command"),
        (other, _) => return try_help(&format!("invalid verification method '{other}'")),
    };
    let settings = Settings {
        state_dir: keystore::state_dir(state_dir),
        tcti: tpm::tcti_from_environment(tcti.as_deref()),
        uhid,
        seat,
        user,
        command,
    };

    // The authenticator thread waits for D-Bus replies while the event
    // loop runs, which needs a multi-threaded runtime.
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
    match runtime.block_on(serve(settings)) {
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
