// SPDX-License-Identifier: Apache-2.0
//! HivemindOS on the web asks to link a browser to a workspace: `passbook://link?request=<id>&relay=<origin>`.
//! Like an authorization link, it names a request and grants nothing. The CLI reads the request from
//! the relay (only relays PassBook trusts), and linking needs the workspace password typed here plus
//! the code the browser shows (passbook_web_link.py). Values never pass through this window.
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::Mutex;
use std::time::Duration;
use zeroize::Zeroizing;

static PENDING: Mutex<Option<(String, String)>> = Mutex::new(None);

fn decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = std::str::from_utf8(bytes.get(index + 1..index + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Exactly `request` (22 URL-safe characters) and `relay` (an https origin), nothing else.
pub fn parse(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("passbook://link?")?;
    let (mut request, mut relay) = (None, None);
    for pair in rest.split('&') {
        let (key, value) = pair.split_once('=')?;
        match key {
            "request" if request.is_none() => request = Some(value),
            "relay" if relay.is_none() => relay = Some(decode(value)?),
            _ => return None,
        }
    }
    let request = request?;
    let relay = relay?;
    let origin_ok = relay.starts_with("https://") && relay.len() <= 200
        && !relay["https://".len()..].contains(|c: char| matches!(c, '/' | '?' | '#' | '@'));
    (request.len() == 22 && request.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') && origin_ok)
        .then(|| (request.to_owned(), relay))
}

pub fn remember(url: &str) -> bool {
    let Some(found) = parse(url) else { return false; };
    if let Ok(mut pending) = PENDING.lock() { *pending = Some(found); }
    true
}

fn refusal(code: Option<&str>) -> &'static str {
    match code {
        Some("authentication-failed") => "The password was not accepted.",
        Some("authentication-required") => "Enter the password for this workspace.",
        Some("code-mismatch") => "The codes do not match. Do not link this browser.",
        Some("request-expired") | Some("request-not-found") => "This link request has expired. Start again from HivemindOS.",
        Some("relay-refused") => "This link does not come from HivemindOS.",
        Some("relay-unavailable") => "HivemindOS could not be reached. Check your connection and try again.",
        Some("workspace-empty") => "This workspace has no keys to share yet.",
        Some("workspace-required") => "Choose one of your workspaces.",
        Some("broker-update-required") => "PassBook needs a restart to finish updating. Run passbook broker restart, sign in, and try again.",
        _ => "This browser could not be linked. Review the request and try again.",
    }
}

fn exchange(action: &str, body: Value) -> Result<Value, String> {
    #[derive(Serialize)]
    struct Envelope<'a> { op: &'a str, action: &'a str, body: Value }
    let input = Zeroizing::new(serde_json::to_vec(&Envelope { op: "managed", action, body })
        .map_err(|_| "This link could not be prepared.")?);
    if input.len() > 16 * 1024 { return Err("This link is too large.".into()); }
    let mut command = crate::passbook_command();
    command.args(["integration", "--json"]);
    let output = crate::authorize::bounded_output(command, input, Duration::from_secs(40))?;
    let result: Value = serde_json::from_slice(&output).map_err(|_| "Update PassBook and try linking again.")?;
    if result.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(refusal(result.get("code").and_then(Value::as_str)).into());
    }
    Ok(result)
}

pub fn inspect() -> Result<Option<Value>, String> {
    let found = PENDING.lock().map_err(|_| "This link is unavailable.")?.clone();
    Ok(found.map(|(request, relay)| exchange("web-link-inspect", json!({"requestId": request, "relay": relay}))
        .unwrap_or_else(|error| json!({"ok": false, "id": request, "error": error}))))
}

pub fn dismiss(id: &str) -> Result<(), String> {
    let mut pending = PENDING.lock().map_err(|_| "This link is unavailable.")?;
    if pending.as_ref().map(|(request, _)| request.as_str()) != Some(id) {
        return Err("The request on screen has changed. Review it again.".into());
    }
    *pending = None;
    Ok(())
}

pub fn decide(id: String, decision: String, workspace: String, code: String, password: String) -> Result<Value, String> {
    let password = Zeroizing::new(password);
    if password.len() > 4096 { return Err("The password is too long.".into()); }
    let relay = {
        let pending = PENDING.lock().map_err(|_| "This link is unavailable.")?;
        match pending.as_ref() {
            Some((request, relay)) if *request == id => relay.clone(),
            _ => return Err("The request on screen has changed. Review it again.".into()),
        }
    };
    let result = exchange("web-link-decide", json!({"requestId": id, "relay": relay, "decision": decision,
        "workspace": workspace, "code": code, "password": password.as_str()}))?;
    if let Ok(mut pending) = PENDING.lock() {
        if pending.as_ref().map(|(request, _)| request.as_str()) == Some(id.as_str()) { *pending = None; }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::parse;
    #[test]
    fn links_carry_exactly_a_request_and_an_https_origin() {
        assert_eq!(parse("passbook://link?request=AbCdEfGhIjKlMnOpQrStUv&relay=https%3A%2F%2Fgateway.example"),
                   Some(("AbCdEfGhIjKlMnOpQrStUv".into(), "https://gateway.example".into())));
        for bad in ["passbook://link?request=short&relay=https%3A%2F%2Fgateway.example",
                    "passbook://link?request=AbCdEfGhIjKlMnOpQrStUv",
                    "passbook://link?request=AbCdEfGhIjKlMnOpQrStUv&relay=http%3A%2F%2Fgateway.example",
                    "passbook://link?request=AbCdEfGhIjKlMnOpQrStUv&relay=https%3A%2F%2Fgateway.example%2Fsteal",
                    "passbook://link?request=AbCdEfGhIjKlMnOpQrStUv&relay=https%3A%2F%2Fgateway.example&password=x",
                    "passbook://authorize?requestId=0123456789abcdef0123456789abcdef"] {
            assert_eq!(parse(bad), None, "{bad}");
        }
    }
}
