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

//! The wording of the authentication dialogs.
//!
//! polkit's authentication agent draws the dialog; gkey only supplies
//! the message.  The agents differ in what they do with it: some show
//! it as plain text, some as markup, none shows an icon or fields of
//! gkey's choosing reliably.  So every message is plain text of a few
//! short lines that reads the same everywhere:
//!
//! ```text
//! Sign in with a passkey
//! Website: example.org
//! Account: alice
//! ```
//!
//! The first line says what is about to happen, the following ones say
//! to whom.  A message has at most [`MAX_LINES`] lines of at most
//! [`MAX_LINE`] characters, which fits the smallest dialogs.
//!
//! Site and account names come from the web page and are untrusted:
//! markup and control characters are neutralized, and a long host name
//! keeps its end, which identifies the site, rather than its start.

/// Most lines in a message.
pub const MAX_LINES: usize = 6;
/// Most characters in a line.
pub const MAX_LINE: usize = 60;

/// Most characters of a host name shown; the end is kept.
const MAX_HOST: usize = 48;
/// Most characters of an account name shown.
const MAX_ACCOUNT: usize = 40;
/// Most characters of a host or account name in a list.
const MAX_LISTED_HOST: usize = 34;
const MAX_LISTED_ACCOUNT: usize = 20;
/// Most passkeys named when deleting several.
const MAX_LISTED: usize = 4;

const ELLIPSIS: char = '\u{2026}';

/// Make text from a web site safe to show in an authentication dialog:
/// some agents render markup, and control characters could disguise
/// the request.  Keeps at most `max` characters, from the start.
pub fn display_text(text: &str, max: usize) -> String {
    let mut out: String = clean(text).take(max).collect();
    if text.chars().count() > max {
        out.push(ELLIPSIS);
    }
    out
}

/// Like [`display_text`], but keeps the end of a long host name, which
/// is the part that identifies the site.
pub fn display_host(text: &str, max: usize) -> String {
    let cleaned: Vec<char> = clean(text).collect();
    if cleaned.len() <= max {
        return cleaned.into_iter().collect();
    }
    let keep = max.saturating_sub(1);
    std::iter::once(ELLIPSIS)
        .chain(cleaned[cleaned.len() - keep..].iter().copied())
        .collect()
}

fn clean(text: &str) -> impl Iterator<Item = char> + '_ {
    text.chars().map(|c| match c {
        '<' => '\u{2039}',
        '>' => '\u{203a}',
        '&' => '+',
        c if c.is_control() => ' ',
        c => c,
    })
}

/// The account line value for a passkey whose user may have no name.
pub fn account(name: Option<&str>) -> String {
    match name.filter(|n| !n.trim().is_empty()) {
        Some(name) => display_text(name, MAX_ACCOUNT),
        None => "not named".into(),
    }
}

/// The account line value when the user will pick among `count`.
pub fn accounts(count: usize) -> String {
    format!("one of {count}")
}

/// A browser asks to create a passkey.
pub fn create(rp_id: &str, account: &str) -> String {
    format!(
        "Create a passkey\nWebsite: {}\nAccount: {account}",
        display_host(rp_id, MAX_HOST)
    )
}

/// A browser asks to sign in with a passkey.
pub fn sign_in(rp_id: &str, account: &str) -> String {
    format!(
        "Sign in with a passkey\nWebsite: {}\nAccount: {account}",
        display_host(rp_id, MAX_HOST)
    )
}

/// A browser tries to create a passkey that already exists.
pub fn already_registered(rp_id: &str) -> String {
    format!(
        "A passkey already exists\nWebsite: {}",
        display_host(rp_id, MAX_HOST)
    )
}

/// A browser asks the user to pick the security key to use.
pub fn choose_key() -> String {
    "Use gkey as your security key".into()
}

/// A browser resets the security key.
pub fn reset() -> String {
    "Delete all passkeys\nEvery passkey stored in gkey will be removed.\nThis cannot be undone."
        .into()
}

/// `gkey list`.
pub fn cli_list() -> String {
    "List your passkeys".into()
}

/// `gkey info`.
pub fn cli_info() -> String {
    "Show information about your keystore".into()
}

/// `gkey init`.
pub fn cli_init() -> String {
    "Create a keystore for your passkeys".into()
}

/// `gkey delete`, naming the passkeys as (site, account) pairs.
pub fn cli_delete(passkeys: &[(&str, Option<&str>)]) -> String {
    let mut out = match passkeys.len() {
        1 => "Delete a passkey".to_string(),
        n => format!("Delete {n} passkeys"),
    };
    for (rp_id, name) in passkeys.iter().take(MAX_LISTED) {
        let account = match name.filter(|n| !n.trim().is_empty()) {
            Some(name) => display_text(name, MAX_LISTED_ACCOUNT),
            None => "not named".into(),
        };
        out.push_str(&format!(
            "\n{} ({account})",
            display_host(rp_id, MAX_LISTED_HOST)
        ));
    }
    if passkeys.len() > MAX_LISTED {
        out.push_str(&format!(
            "\n{ELLIPSIS} and {} more",
            passkeys.len() - MAX_LISTED
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts() {
        assert_eq!(
            create("example.org", &account(Some("alice"))),
            "Create a passkey\nWebsite: example.org\nAccount: alice"
        );
        assert_eq!(
            sign_in("example.org", &accounts(3)),
            "Sign in with a passkey\nWebsite: example.org\nAccount: one of 3"
        );
        assert_eq!(
            sign_in("example.org", &account(None)),
            "Sign in with a passkey\nWebsite: example.org\nAccount: not named"
        );
        assert_eq!(
            already_registered("example.org"),
            "A passkey already exists\nWebsite: example.org"
        );
        assert_eq!(
            cli_delete(&[("example.org", Some("alice"))]),
            "Delete a passkey\nexample.org (alice)"
        );
        assert_eq!(
            cli_delete(&[("a.org", Some("x")), ("b.org", None)]),
            "Delete 2 passkeys\na.org (x)\nb.org (not named)"
        );
    }

    #[test]
    fn long_delete_lists_are_cut() {
        let many: Vec<(&str, Option<&str>)> = (0..9).map(|_| ("example.org", Some("a"))).collect();
        let message = cli_delete(&many);
        assert_eq!(message.lines().count(), 1 + MAX_LISTED + 1);
        assert!(message.ends_with("\u{2026} and 5 more"));
    }

    #[test]
    fn hosts_keep_their_end() {
        let host = "login.example.org.very-long-subdomain-to-hide-the-end.attacker.com";
        let shown = display_host(host, 30);
        assert_eq!(shown.chars().count(), 30);
        assert!(shown.starts_with('\u{2026}'));
        assert!(shown.ends_with("attacker.com"));
        assert_eq!(display_host("example.org", 30), "example.org");
        // Accounts keep their start.
        assert_eq!(display_text("abcdef", 3), "abc\u{2026}");
    }

    #[test]
    fn untrusted_text_is_neutralized() {
        assert_eq!(
            display_text("<b>evil</b>&\u{1b}[31m\nline", 64),
            "\u{2039}b\u{203a}evil\u{2039}/b\u{203a}+ [31m line"
        );
        // A site cannot add lines or fake a second message.
        let message = create("a.org\nAccount: root", &account(Some("x\ny")));
        assert_eq!(message.lines().count(), 3);
    }

    #[test]
    fn messages_fit_the_dialog() {
        let wide = "w".repeat(500);
        let long_host = format!("{wide}.org");
        let name = Some(wide.as_str());
        let many: Vec<(&str, Option<&str>)> = (0..20).map(|_| (long_host.as_str(), name)).collect();
        let messages = [
            create(&long_host, &account(name)),
            sign_in(&long_host, &account(name)),
            already_registered(&long_host),
            choose_key(),
            reset(),
            cli_list(),
            cli_info(),
            cli_init(),
            cli_delete(&many),
        ];
        for message in &messages {
            assert!(message.lines().count() <= MAX_LINES, "{message}");
            for line in message.lines() {
                assert!(line.chars().count() <= MAX_LINE, "{line}");
            }
        }
    }
}
