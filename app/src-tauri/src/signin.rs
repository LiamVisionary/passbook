// SPDX-License-Identifier: Apache-2.0
//! An agent asks the person to open the vault: `passbook://signin?by=…&reason=…&workspace=…`.
//!
//! The agent cannot be handed the password: everything it reads is written into its
//! transcript. So it opens this link (`passbook signin --ask`, or the MCP server's
//! `request_signin`), this window comes forward on the lock screen's sign-in card with who
//! is asking and why, and the person approves there with Touch ID or the password, the same
//! sign-in as ever. The agent learns only that the vault opened.
//!
//! Like every link, it grants nothing and carries no value. `by` and `reason` are the
//! asker's own words and the window says so; any program can open a link, so what guards
//! the vault is the person choosing Not now. The limits here are the CLI's
//! (src/passbook_signin_ask.py), and tests/test_passbook_signin_ask.py holds the two
//! together.
use serde::Serialize;
use std::sync::Mutex;

const MAX_BY: usize = 60;
const MAX_REASON: usize = 200;
const MAX_WORKSPACE: usize = 64;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SigninAsk {
    pub id: String,
    pub by: String,
    pub reason: String,
    pub workspace: String,
}

/// One at a time: a second request replaces the first rather than queueing, so the card
/// on screen is always the latest ask and a pile of them cannot build up.
static PENDING: Mutex<Option<SigninAsk>> = Mutex::new(None);

fn decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let hex = std::str::from_utf8(bytes.get(index + 1..index + 3)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                index += 3;
            }
            b'+' => { out.push(b' '); index += 1; }
            byte => { out.push(byte); index += 1; }
        }
    }
    String::from_utf8(out).ok()
}

/// One readable line: control and format characters (bidi overrides among them) become
/// spaces, runs of space collapse, and anything past `limit` characters is refused rather
/// than trimmed, because the CLI already trims and a longer one did not come from it.
fn line(raw: &str, limit: usize) -> Option<String> {
    let kept: String = raw.chars().map(|c| if c.is_control() || is_format(c) { ' ' } else { c }).collect();
    let words = kept.split_whitespace().collect::<Vec<_>>().join(" ");
    (words.chars().count() <= limit).then_some(words)
}

/// Unicode's format characters that matter on screen: the bidi controls, which can make a
/// reason read backwards, and the zero-width ones, which can hide text inside it.
fn is_format(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}' | '\u{00AD}')
}

/// Exactly `by`, `reason` and `workspace`, each at most once; anything else is not ours.
pub fn parse(url: &str, id: &str) -> Option<SigninAsk> {
    let rest = match url.strip_prefix("passbook://signin")? {
        "" => "",
        rest => rest.strip_prefix('?')?,
    };
    let (mut by, mut reason, mut workspace) = (None, None, None);
    for pair in rest.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=')?;
        let slot = match key { "by" => &mut by, "reason" => &mut reason, "workspace" => &mut workspace, _ => return None };
        if slot.is_some() { return None; }
        *slot = Some(decode(value)?);
    }
    let workspace = workspace.unwrap_or_default();
    let workspace_ok = workspace.is_empty() || (workspace.len() <= MAX_WORKSPACE
        && workspace.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-')));
    if !workspace_ok { return None; }
    let by = line(&by.unwrap_or_default(), MAX_BY)?;
    let reason = line(&reason.unwrap_or_default(), MAX_REASON)?;
    Some(SigninAsk {
        id: id.to_owned(),
        by: if by.is_empty() { "A program on this computer".into() } else { by },
        reason,
        workspace,
    })
}

pub fn remember(url: &str, id: &str) -> bool {
    let Some(found) = parse(url, id) else { return false; };
    if let Ok(mut pending) = PENDING.lock() { *pending = Some(found); }
    true
}

pub fn pending() -> Option<SigninAsk> {
    PENDING.lock().ok().and_then(|slot| slot.clone())
}

/// Clears the ask on screen, and only that one: a newer ask that arrived meanwhile stays.
pub fn dismiss(id: &str) {
    if let Ok(mut pending) = PENDING.lock() {
        if pending.as_ref().map(|ask| ask.id.as_str()) == Some(id) { *pending = None; }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_what_the_cli_writes() {
        let ask = parse("passbook://signin?by=Claude%20Code&reason=read%20the%20copy%2Dtrading%20state&workspace=main", "1").unwrap();
        assert_eq!(ask.by, "Claude Code");
        assert_eq!(ask.reason, "read the copy-trading state");
        assert_eq!(ask.workspace, "main");
    }

    #[test]
    fn every_part_is_optional() {
        let ask = parse("passbook://signin", "1").unwrap();
        assert_eq!(ask.by, "A program on this computer");
        assert_eq!(ask.reason, "");
        assert_eq!(ask.workspace, "");
        assert!(parse("passbook://signin?", "1").is_some());
    }

    #[test]
    fn refuses_anything_else() {
        assert!(parse("passbook://signin?password=hunter2", "1").is_none());
        assert!(parse("passbook://signin?by=a&by=b", "1").is_none());
        assert!(parse("passbook://signinx?by=a", "1").is_none());
        assert!(parse("passbook://add?key=A", "1").is_none());
        assert!(parse("passbook://signin?workspace=../etc", "1").is_none());
        assert!(parse("passbook://signin?workspace=a%2Fb", "1").is_none());
        assert!(parse("passbook://signin?reason=%ZZ", "1").is_none());
    }

    #[test]
    fn a_reason_reads_as_one_plain_line() {
        let ask = parse("passbook://signin?reason=one%0A%0Atwo%E2%80%AEevil", "1").unwrap();
        assert_eq!(ask.reason, "one two evil");
    }

    #[test]
    fn too_long_is_refused_not_trimmed() {
        let long = "a".repeat(MAX_REASON + 1);
        assert!(parse(&format!("passbook://signin?reason={long}"), "1").is_none());
        let fits = "a".repeat(MAX_REASON);
        assert!(parse(&format!("passbook://signin?reason={fits}"), "1").is_some());
        assert!(parse(&format!("passbook://signin?by={}", "b".repeat(MAX_BY + 1)), "1").is_none());
    }

    #[test]
    fn dismiss_leaves_a_newer_ask() {
        assert!(remember("passbook://signin?reason=first", "first"));
        assert!(remember("passbook://signin?reason=second", "second"));
        dismiss("first");
        assert_eq!(pending().map(|ask| ask.reason), Some("second".into()));
        dismiss("second");
        assert!(pending().is_none());
    }
}
