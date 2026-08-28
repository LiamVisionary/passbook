// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rizzma, Inc.
//! "Add to PassBook" — a page asks for keys, a person decides.
//!
//! A platform's API page knows exactly which credentials its SDK reads. Today
//! it prints them and you copy them into a `.env` by hand, which is how keys
//! end up in repositories. A link can carry that list instead:
//!
//! ```text
//! passbook://add?app=OpenAI&site=https://platform.openai.com/api-keys
//!               &key=OPENAI_API_KEY&key=OPENAI_ORG_ID
//! ```
//!
//! ## Two ways in, and why there are two
//!
//! The point of the feature is that nobody types a credential: the page that
//! just minted the key hands it straight over. But a URL is the wrong pipe for
//! one. Windows gives a URL handler its argument as a command line, which
//! every process on the machine can read, and this project's own CLI already
//! says of `passbook add KEY=value` that *a value passed as KEY=value is
//! visible in shell history and, briefly, to `ps`*.
//!
//! So the values do not travel by URL. They travel by loopback:
//!
//!   * **`POST http://127.0.0.1:17817/ask`** — names *and* values, in a request
//!     body, over an interface that does not leave the machine. Nothing is put
//!     in an argument list, a URL, or a log. Better still, the browser sets
//!     `Origin`, so who is asking is the browser's word rather than the page's.
//!     This is the path the button takes.
//!   * **`passbook://add?key=NAME`** — names only, and its job is to *start*
//!     the app when it is not running, so the page can then post to it. A link
//!     may never carry a value, and `parse` drops one if it tries.
//!
//! Either way the request lands here, is reduced to something a person can
//! read, and waits for them.
//!
//! ## What arrives here is untrusted
//!
//! Anything can open a URL. This module's job is to reduce whatever turns up
//! to something a person can read and judge: a bounded number of well-formed
//! key names, a label, and an origin. It never fetches `site`, and nothing is
//! added to any store until somebody approves it and opens the vault.

use serde::{Deserialize, Serialize};

/// Enough for a large SDK, few enough that the window can show them all.
/// Beyond this the request is not a credential list, it is a payload.
const MAX_KEYS: usize = 25;
/// Long enough for a real environment variable, short enough to render.
const MAX_NAME: usize = 128;
/// What is shown as "who is asking". Truncated rather than refused, because a
/// silly label should not stop a person seeing an otherwise sensible request.
const MAX_LABEL: usize = 80;
const MAX_NOTE: usize = 200;
/// Generous for an API key, far short of a file.
const MAX_VALUE: usize = 8 * 1024;

/// One key a page would like stored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Wanted {
    pub name: String,
    /// The credential itself, when the page handed one over.
    ///
    /// Never serialised. The window renders a request, and a window is a thing
    /// people screen-share; it has no reason to hold the value it is about to
    /// store, so the value stays in this process and `apply_ask` reads it from
    /// here. What the window gets is `preview`.
    #[serde(skip_serializing, default)]
    pub value: Option<String>,
    pub has_value: bool,
    /// Enough to recognise a key without showing it: `sk-pr…4f21`.
    pub preview: String,
}

/// A request as it will be shown, with everything unusable already removed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ask {
    /// Distinguishes one request from the next, so an answer cannot be applied
    /// to a request that has since been replaced.
    pub id: String,
    /// `page` when a browser handed this over on the loopback interface, where
    /// the origin is the browser's word. `link` when it arrived as a URL, where
    /// the origin is only a claim. The window says which.
    pub source: String,
    /// Who says they are asking. A claim, shown as one.
    pub app: String,
    /// The page it came from, shown so the origin can be judged. Never fetched.
    pub site: String,
    /// The origin on its own, because that is the part that means anything.
    pub origin: String,
    pub note: String,
    /// A workspace the link suggests. The window still defaults to the active
    /// one; this is only a hint, and an unknown name is ignored.
    pub workspace: String,
    pub keys: Vec<Wanted>,
    /// Names the link asked for that were dropped, so the window can say the
    /// request was trimmed rather than silently showing less than was sent.
    pub refused: Vec<String>,
}

/// Percent-decoding, plus `+` for space, which query strings use and URL
/// decoders often forget.
fn decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// An environment variable name, and nothing else.
///
/// Shell syntax is the whole point of the format, so the rule is shell's:
/// a letter or underscore, then letters, digits and underscores. Rejecting the
/// rest here means a name cannot carry a newline into a `KEY=value` stream and
/// smuggle a second assignment past the person reading the list.
fn usable_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Enough of a value to tell two keys apart, and not enough to use.
///
/// Short values get nothing but their length, because the ends of a six
/// character secret are the whole secret.
fn preview_of(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() < 12 {
        return format!("{} characters", chars.len());
    }
    let head: String = chars.iter().take(5).collect();
    let tail: String = chars.iter().skip(chars.len() - 4).collect();
    format!("{head}…{tail}")
}

/// A credential this store can actually hold.
///
/// The file format is one `KEY=value` per line and its reader strips escapes
/// rather than decoding them, so a newline in a value cannot survive a
/// round trip. Refusing it here is the honest answer; storing half a private
/// key is not.
fn usable_value(value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("is empty");
    }
    if value.len() > MAX_VALUE {
        return Err("is too long to store");
    }
    if value.contains(['\n', '\r', '\0']) {
        return Err("spans more than one line, which this store cannot hold");
    }
    Ok(())
}

/// Cut a display string to length, on a character boundary.
fn trim_to(value: &str, limit: usize) -> String {
    let cleaned: String = value
        .chars()
        // A control character in a label is either a mistake or an attempt to
        // make the request render as something other than what it is.
        .filter(|c| !c.is_control())
        .collect();
    if cleaned.chars().count() <= limit {
        return cleaned;
    }
    cleaned.chars().take(limit).collect::<String>() + "…"
}

/// `https://host/path?x` reduced to `https://host`, which is the part worth
/// showing. Anything that is not plain http(s) is dropped rather than shown,
/// because a `javascript:` or `data:` "origin" in a trust prompt is a lie.
fn origin_of(site: &str) -> String {
    for scheme in ["https://", "http://"] {
        if let Some(rest) = site.strip_prefix(scheme) {
            let host: String = rest
                .chars()
                .take_while(|c| !matches!(c, '/' | '?' | '#'))
                .collect();
            if host.is_empty() || host.contains(|c: char| c.is_whitespace()) {
                return String::new();
            }
            return format!("{scheme}{host}");
        }
    }
    String::new()
}

/// Read `passbook://add?…` into something showable, or explain why not.
///
/// `id` is supplied rather than generated so this stays a pure function and
/// the tests can name the request they are checking.
pub fn parse(url: &str, id: &str) -> Result<Ask, String> {
    let rest = url
        .strip_prefix("passbook://")
        .or_else(|| url.strip_prefix("passbook:"))
        .ok_or("That link is not a PassBook link.")?;
    // `passbook://add?x` and `passbook:add?x` both land here; the leading
    // slashes of the first are already gone.
    let rest = rest.trim_start_matches('/');
    let (action, query) = match rest.split_once('?') {
        Some((action, query)) => (action, query),
        None => (rest, ""),
    };
    if action.trim_end_matches('/') != "add" {
        return Err(format!("PassBook does not know how to {action}."));
    }

    let mut app = String::new();
    let mut site = String::new();
    let mut note = String::new();
    let mut workspace = String::new();
    let mut keys: Vec<Wanted> = Vec::new();
    let mut refused: Vec<String> = Vec::new();

    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (raw_name, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = decode(raw_value);
        match decode(raw_name).as_str() {
            "app" => app = trim_to(&value, MAX_LABEL),
            "site" => site = trim_to(&value, 400),
            "note" => note = trim_to(&value, MAX_NOTE),
            "workspace" => workspace = trim_to(&value, MAX_LABEL),
            "key" => {
                // `key=NAME=VALUE` is the shape a caller reaches for, because
                // it is what `passbook add` and every .env file look like. It
                // is refused rather than ignored, so the mistake is visible on
                // screen instead of producing a key with no value.
                if let Some((name, _)) = value.split_once('=') {
                    refused.push(trim_to(name, MAX_NAME));
                    continue;
                }
                let name = value.trim().to_string();
                if !usable_name(&name) {
                    refused.push(trim_to(&name, MAX_NAME));
                    continue;
                }
                if keys.iter().any(|k| k.name == name) {
                    continue;
                }
                if keys.len() >= MAX_KEYS {
                    refused.push(name);
                    continue;
                }
                keys.push(Wanted { name, value: None, has_value: false, preview: String::new() });
            }
            // Unknown parameters are ignored rather than refused, so a newer
            // page can add one without an older app calling the link broken.
            _ => {}
        }
    }

    if keys.is_empty() {
        return Err("That link did not name any keys PassBook could add.".into());
    }

    let origin = origin_of(&site);
    if origin.is_empty() {
        // Shown as "somewhere unnamed" rather than the raw string, so an
        // attacker cannot put a convincing-looking hostname in a field that
        // was never an origin.
        site = String::new();
    }
    Ok(Ask {
        id: id.to_string(),
        source: "link".into(),
        app: if app.is_empty() { "A website".into() } else { app },
        site,
        origin,
        note,
        workspace,
        keys,
        refused,
    })
}


/// Read what a page posted on the loopback interface.
///
/// `origin` comes from the browser's `Origin` header rather than from the
/// body, which is the whole reason this path is better than a link: a page can
/// claim any `app` label it likes, and cannot claim to be a domain it is not.
pub fn parse_page(body: &str, origin: &str, id: &str) -> Result<Ask, String> {
    #[derive(Deserialize)]
    struct SentKey {
        name: String,
        #[serde(default)]
        value: String,
    }
    #[derive(Deserialize)]
    struct Sent {
        #[serde(default)]
        app: String,
        #[serde(default)]
        note: String,
        #[serde(default)]
        workspace: String,
        #[serde(default)]
        keys: Vec<SentKey>,
    }

    let sent: Sent = serde_json::from_str(body)
        .map_err(|_| "That request was not something PassBook could read.".to_string())?;

    let mut keys: Vec<Wanted> = Vec::new();
    let mut refused: Vec<String> = Vec::new();
    for entry in sent.keys {
        let name = entry.name.trim().to_string();
        if !usable_name(&name) || keys.iter().any(|k| k.name == name) {
            if !name.is_empty() {
                refused.push(trim_to(&name, MAX_NAME));
            }
            continue;
        }
        if keys.len() >= MAX_KEYS {
            refused.push(name);
            continue;
        }
        // A key with no value is legitimate: a docs page knows the names its
        // SDK reads without knowing anybody's account.
        if entry.value.is_empty() {
            keys.push(Wanted { name, value: None, has_value: false, preview: String::new() });
            continue;
        }
        match usable_value(&entry.value) {
            Ok(()) => {
                let preview = preview_of(&entry.value);
                keys.push(Wanted { name, value: Some(entry.value), has_value: true, preview });
            }
            // Named in the refusal list so the window can say which one and
            // why, rather than showing a shorter list than was sent.
            Err(_) => refused.push(name),
        }
    }
    if keys.is_empty() {
        return Err("That request did not name any keys PassBook could add.".into());
    }

    let origin = origin_of(origin);
    if origin.is_empty() {
        return Err("PassBook could not tell which site that came from.".into());
    }
    Ok(Ask {
        id: id.to_string(),
        source: "page".into(),
        app: if sent.app.trim().is_empty() { origin.clone() } else { trim_to(&sent.app, MAX_LABEL) },
        site: origin.clone(),
        origin,
        note: trim_to(&sent.note, MAX_NOTE),
        workspace: trim_to(&sent.workspace, MAX_LABEL),
        keys,
        refused,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(url: &str) -> Result<Ask, String> {
        parse(url, "test")
    }

    #[test]
    fn reads_the_ordinary_shape() {
        let got = ask("passbook://add?app=OpenAI&site=https://platform.openai.com/api-keys\
                       &key=OPENAI_API_KEY&key=OPENAI_ORG_ID")
            .expect("should parse");
        assert_eq!(got.app, "OpenAI");
        assert_eq!(got.origin, "https://platform.openai.com");
        assert_eq!(got.keys.len(), 2);
        assert_eq!(got.keys[0].name, "OPENAI_API_KEY");
    }

    #[test]
    fn a_value_in_the_link_is_refused_not_stored() {
        // The whole security position of this feature. If this ever passes a
        // value through, a credential has been put somewhere `ps` can read it.
        let got = ask("passbook://add?key=OPENAI_API_KEY%3Dsk-live-secret").expect_err("no keys");
        assert!(got.contains("did not name any keys"), "{got}");

        let mixed = ask("passbook://add?key=GOOD_KEY&key=BAD%3Dsecret").expect("one good key");
        assert_eq!(mixed.keys.len(), 1);
        assert_eq!(mixed.keys[0].name, "GOOD_KEY");
        assert_eq!(mixed.refused, vec!["BAD"]);
        let rendered = serde_json::to_string(&mixed).unwrap();
        assert!(!rendered.contains("secret"), "a value reached the window: {rendered}");
    }

    #[test]
    fn a_name_cannot_smuggle_a_second_assignment() {
        // These are written to the CLI as `KEY=value` lines. A newline in a
        // name would add a key the person never saw.
        let got = ask("passbook://add?key=A%0AEVIL%3Dvalue&key=REAL").expect("one key");
        assert_eq!(got.keys.len(), 1);
        assert_eq!(got.keys[0].name, "REAL");
    }

    #[test]
    fn names_are_environment_variables_and_nothing_else() {
        for bad in ["with space", "dash-name", "1LEADING", "semi;colon", "quote\"", ""] {
            let url = format!("passbook://add?key={}&key=OK", urlish(bad));
            let got = ask(&url).expect("OK survives");
            assert_eq!(got.keys.len(), 1, "{bad} was accepted");
        }
    }

    fn urlish(value: &str) -> String {
        value
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c.to_string() } else { format!("%{:02X}", c as u32) })
            .collect()
    }

    #[test]
    fn only_http_origins_are_shown() {
        for hostile in ["javascript:alert(1)", "data:text/html,x", "file:///etc/passwd"] {
            let url = format!("passbook://add?key=K&site={}", urlish(hostile));
            let got = ask(&url).expect("parses");
            assert!(got.origin.is_empty(), "{hostile} was shown as an origin");
            assert!(got.site.is_empty(), "{hostile} was shown at all");
        }
    }

    #[test]
    fn the_list_is_bounded() {
        let many: Vec<String> = (0..60).map(|i| format!("key=K{i}")).collect();
        let got = ask(&format!("passbook://add?{}", many.join("&"))).expect("parses");
        assert_eq!(got.keys.len(), MAX_KEYS);
        assert_eq!(got.refused.len(), 60 - MAX_KEYS);
    }

    #[test]
    fn duplicates_collapse() {
        let got = ask("passbook://add?key=SAME&key=SAME&key=OTHER").expect("parses");
        assert_eq!(got.keys.len(), 2);
    }

    #[test]
    fn a_link_with_no_keys_is_an_error_not_an_empty_prompt() {
        assert!(ask("passbook://add?app=Nobody").is_err());
    }

    #[test]
    fn other_actions_are_refused() {
        assert!(ask("passbook://reveal?key=SECRET").is_err());
        assert!(ask("https://example.com/add?key=K").is_err());
    }

    #[test]
    fn control_characters_cannot_dress_up_a_label() {
        let got = ask("passbook://add?key=K&app=Stripe%0A%0AVerified%20by%20Apple").expect("parses");
        assert!(!got.app.contains('\n'));
    }

    #[test]
    fn a_page_may_hand_over_values() {
        let got = parse_page(
            r#"{"app":"OpenAI","keys":[{"name":"OPENAI_API_KEY","value":"sk-proj-abcdefghijklmnop"}]}"#,
            "https://platform.openai.com/api-keys", "t").expect("parses");
        assert_eq!(got.source, "page");
        assert_eq!(got.origin, "https://platform.openai.com");
        assert!(got.keys[0].has_value);
        assert_eq!(got.keys[0].value.as_deref(), Some("sk-proj-abcdefghijklmnop"));
    }

    #[test]
    fn the_value_never_reaches_the_window() {
        // The window renders this and a window gets screen-shared. It has no
        // business holding the credential it is about to store.
        let got = parse_page(
            r#"{"keys":[{"name":"K","value":"sk-proj-abcdefghijklmnop"}]}"#,
            "https://example.com", "t").expect("parses");
        let rendered = serde_json::to_string(&got).unwrap();
        assert!(!rendered.contains("sk-proj-abcdefghijklmnop"), "{rendered}");
        assert!(rendered.contains("has_value"));
        assert!(rendered.contains("sk-pr…mnop"), "a preview should survive: {rendered}");
    }

    #[test]
    fn a_short_value_previews_as_a_length_not_as_itself() {
        let got = parse_page(r#"{"keys":[{"name":"K","value":"hunter2"}]}"#,
                             "https://example.com", "t").expect("parses");
        assert_eq!(got.keys[0].preview, "7 characters");
    }

    #[test]
    fn the_origin_is_the_browsers_word_not_the_pages() {
        // `app` is a label the page chose. It must not be able to pass itself
        // off as a domain.
        let got = parse_page(r#"{"app":"https://stripe.com","keys":[{"name":"K"}]}"#,
                             "https://totally-not-stripe.example", "t").expect("parses");
        assert_eq!(got.origin, "https://totally-not-stripe.example");
    }

    #[test]
    fn a_page_with_no_usable_origin_is_refused() {
        assert!(parse_page(r#"{"keys":[{"name":"K"}]}"#, "null", "t").is_err());
        assert!(parse_page(r#"{"keys":[{"name":"K"}]}"#, "", "t").is_err());
    }

    #[test]
    fn a_multiline_value_is_refused_rather_than_half_stored() {
        // The store is one KEY=value per line and its reader strips escapes,
        // so a newline cannot survive. Better to say so than to write half.
        let got = parse_page(
            r#"{"keys":[{"name":"PEM","value":"-----BEGIN-----\nabc\n-----END-----"},{"name":"OK","value":"fine-value-here"}]}"#,
            "https://example.com", "t").expect("parses");
        assert_eq!(got.keys.len(), 1);
        assert_eq!(got.keys[0].name, "OK");
        assert_eq!(got.refused, vec!["PEM"]);
    }
}
