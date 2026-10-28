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

//! Command line parsing following the GNU conventions, as implemented
//! by getopt_long(3): long options may be abbreviated as long as the
//! abbreviation is unique, take arguments as `--name=value` or
//! `--name value`, short options may be grouped, and options and
//! operands may be intermixed unless `POSIXLY_CORRECT` is set.  `--`
//! ends option processing.

/// Whether an option takes an argument.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HasArg {
    No,
    Required,
}

/// Description of one option.
pub struct Opt {
    pub long: &'static str,
    pub short: Option<char>,
    pub has_arg: HasArg,
}

/// One parsed element of the command line.
#[derive(Debug, PartialEq, Eq)]
pub enum Item {
    /// An option, identified by its long name, and its argument.
    Opt(&'static str, Option<String>),
    /// An operand.
    Operand(String),
}

fn find_long<'a>(options: &'a [Opt], name: &str) -> Result<&'a Opt, String> {
    if let Some(exact) = options.iter().find(|o| o.long == name) {
        return Ok(exact);
    }
    let candidates: Vec<&Opt> = options
        .iter()
        .filter(|o| o.long.starts_with(name))
        .collect();
    match candidates.as_slice() {
        [one] => Ok(one),
        [] => Err(format!("unrecognized option '--{name}'")),
        many => {
            let names: Vec<String> = many.iter().map(|o| format!("'--{}'", o.long)).collect();
            Err(format!(
                "option '--{name}' is ambiguous; possibilities: {}",
                names.join(" ")
            ))
        }
    }
}

/// Parse `args` (without the program name) against `options`.
/// Errors are returned as messages suitable for printing after the
/// program name.
pub fn parse<I>(args: I, options: &[Opt]) -> Result<Vec<Item>, String>
where
    I: IntoIterator<Item = String>,
{
    let posixly_correct = std::env::var_os("POSIXLY_CORRECT").is_some();
    let mut items = Vec::new();
    let mut args = args.into_iter();
    let mut only_operands = false;
    while let Some(arg) = args.next() {
        if only_operands || arg == "-" || !arg.starts_with('-') {
            if posixly_correct {
                only_operands = true;
            }
            items.push(Item::Operand(arg));
            continue;
        }
        if arg == "--" {
            only_operands = true;
            continue;
        }
        if let Some(body) = arg.strip_prefix("--") {
            let (name, inline) = match body.split_once('=') {
                Some((name, value)) => (name, Some(value.to_string())),
                None => (body, None),
            };
            let opt = find_long(options, name)?;
            let value = match (opt.has_arg, inline) {
                (HasArg::No, Some(_)) => {
                    return Err(format!("option '--{}' doesn't allow an argument", opt.long))
                }
                (HasArg::No, None) => None,
                (HasArg::Required, Some(value)) => Some(value),
                (HasArg::Required, None) => Some(
                    args.next()
                        .ok_or_else(|| format!("option '--{}' requires an argument", opt.long))?,
                ),
            };
            items.push(Item::Opt(opt.long, value));
            continue;
        }
        let chars = arg[1..].char_indices();
        for (at, c) in chars {
            let opt = options
                .iter()
                .find(|o| o.short == Some(c))
                .ok_or_else(|| format!("invalid option -- '{c}'"))?;
            if opt.has_arg == HasArg::No {
                items.push(Item::Opt(opt.long, None));
                continue;
            }
            let rest = &arg[1 + at + c.len_utf8()..];
            let value = if rest.is_empty() {
                args.next()
                    .ok_or_else(|| format!("option requires an argument -- '{c}'"))?
            } else {
                rest.to_string()
            };
            items.push(Item::Opt(opt.long, Some(value)));
            break;
        }
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPTIONS: &[Opt] = &[
        Opt {
            long: "help",
            short: Some('h'),
            has_arg: HasArg::No,
        },
        Opt {
            long: "verbose",
            short: Some('v'),
            has_arg: HasArg::No,
        },
        Opt {
            long: "verify",
            short: None,
            has_arg: HasArg::Required,
        },
        Opt {
            long: "keystore",
            short: Some('k'),
            has_arg: HasArg::Required,
        },
    ];

    fn run(args: &[&str]) -> Result<Vec<Item>, String> {
        parse(args.iter().map(|s| s.to_string()), OPTIONS)
    }

    #[test]
    fn long_options() {
        assert_eq!(
            run(&["--keystore=/a", "list", "--key", "/b", "--he"]).unwrap(),
            vec![
                Item::Opt("keystore", Some("/a".into())),
                Item::Operand("list".into()),
                Item::Opt("keystore", Some("/b".into())),
                Item::Opt("help", None),
            ]
        );
        assert!(run(&["--ver"]).unwrap_err().contains("ambiguous"));
        assert!(run(&["--help=x"]).is_err());
        assert!(run(&["--nope"]).is_err());
        assert!(run(&["--verify"]).is_err());
    }

    #[test]
    fn short_options() {
        assert_eq!(
            run(&["-vk/a", "-k", "/b", "--", "-v"]).unwrap(),
            vec![
                Item::Opt("verbose", None),
                Item::Opt("keystore", Some("/a".into())),
                Item::Opt("keystore", Some("/b".into())),
                Item::Operand("-v".into()),
            ]
        );
        assert!(run(&["-x"]).is_err());
    }
}
