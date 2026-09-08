// SPDX-License-Identifier: Apache-2.0
//! Opaque authorization links share the existing CLI and owner-password path.
use serde::Serialize;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

static PENDING: Mutex<Option<String>> = Mutex::new(None);
const MAX_OUTPUT: usize = 128 * 1024;

fn bounded_output(mut command: Command, input: Zeroizing<Vec<u8>>, timeout: Duration) -> Result<Vec<u8>, String> {
    let mut child = command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().map_err(|_| "PassBook could not start this app authorization.")?;
    let stdin = child.stdin.take();
    // Both pipes run independently, so a blocked stdin write or a CLI that
    // floods stdout cannot bypass the wall-clock and allocation bounds below.
    std::thread::spawn(move || { if let Some(mut pipe) = stdin { let _ = pipe.write_all(&input); } });
    let stdout = child.stdout.take().ok_or("PassBook could not answer this request.")?;
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.take((MAX_OUTPUT + 1) as u64).read_to_end(&mut bytes).map(|_| bytes);
        let _ = sender.send(result);
    });
    let deadline = Instant::now() + timeout;
    let mut output = None;
    loop {
        if output.is_none() {
            match receiver.try_recv() {
                Ok(Ok(bytes)) if bytes.len() <= MAX_OUTPUT => output = Some(bytes),
                Ok(_) | Err(mpsc::TryRecvError::Disconnected) => {
                    let _ = child.kill(); let _ = child.wait();
                    return Err("PassBook returned an invalid app authorization.".into());
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if output.is_some() && child.try_wait().ok().flatten().is_some() { return Ok(output.unwrap()); }
        if Instant::now() >= deadline {
            let _ = child.kill(); let _ = child.wait();
            return Err("PassBook did not finish this app authorization. Check its status and try again.".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn refusal(code: Option<&str>) -> &'static str {
    match code {
        Some("authentication-failed") => "The password was not accepted.",
        Some("authentication-required") => "Enter your PassBook password (at least 8 characters for a new workspace).",
        Some("request-expired") => "This app authorization expired. Start again in HivemindOS.",
        Some("already-resolved") => "This app authorization has already been answered.",
        Some("request-not-found") => "This app authorization is no longer available.",
        Some("authorization-busy") => "Wait, then start a new app authorization in HivemindOS.",
        Some("workspace-recovery-required") => "Recover the existing workspace before connecting this app.",
        Some("already-connected") => "Disconnect this app before choosing another workspace.",
        Some("background-unavailable") => "Background access is unavailable. Connect without it or use a supported device.",
        Some("broker-update-required") => "Finish updating PassBook and try again.",
        _ => "This app authorization could not finish. Review the request and try again.",
    }
}

pub fn link_id(url: &str) -> Option<&str> {
    let id = url.strip_prefix("passbook://authorize?requestId=")?;
    (id.len() == 32 && id.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())).then_some(id)
}

pub fn remember(url: &str) -> bool {
    let Some(id) = link_id(url) else { return false; };
    if let Ok(mut pending) = PENDING.lock() { *pending = Some(id.to_owned()); }
    true
}

fn exchange(action: &str, body: impl Serialize) -> Result<Value, String> {
    #[derive(Serialize)]
    struct Envelope<'a, T> { op: &'a str, action: &'a str, body: T }
    let input = Zeroizing::new(serde_json::to_vec(&Envelope { op: "managed", action, body })
        .map_err(|_| "This app authorization could not be prepared.")?);
    if input.len() > 16 * 1024 { return Err("This app authorization is too large.".into()); }
    let mut command = crate::passbook_command();
    command.args(["integration", "--json"]);
    let output = bounded_output(command, input, Duration::from_secs(40))?;
    let result: Value = serde_json::from_slice(&output).map_err(|_| "Update PassBook and try authorizing this app again.")?;
    if result.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(refusal(result.get("code").and_then(Value::as_str)).into());
    }
    Ok(result)
}

pub fn inspect() -> Result<Option<Value>, String> {
    let id = PENDING.lock().map_err(|_| "This app authorization is unavailable.")?.clone();
    Ok(id.map(|id| exchange("authorize-inspect", json!({"requestId": id}))
        .unwrap_or_else(|error| json!({"ok": false, "id": id, "error": error}))))
}

pub fn dismiss(id: &str) -> Result<(), String> {
    let mut pending = PENDING.lock().map_err(|_| "This app authorization is unavailable.")?;
    if pending.as_deref() != Some(id) { return Err("The request on screen has changed. Review it again.".into()); }
    *pending = None;
    Ok(())
}

pub fn decide(id: String, decision: String, workspace: String, create_workspace: bool,
              background: bool, consent: bool, password: String) -> Result<Value, String> {
    let password = Zeroizing::new(password);
    if password.len() > 4096 { return Err("The password is too long.".into()); }
    {
        let pending = PENDING.lock().map_err(|_| "This app authorization is unavailable.")?;
        if pending.as_deref() != Some(&id) { return Err("The request on screen has changed. Review it again.".into()); }
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Decision<'a> { request_id: &'a str, decision: &'a str, workspace: &'a str,
        create_workspace: bool, background: bool, consent: bool, password: &'a str }
    let result = exchange("authorize-decide", Decision { request_id: &id, decision: &decision,
        workspace: &workspace, create_workspace, background, consent, password: &password })?;
    // The owner approved this exact ID. A link arriving while the CLI runs is
    // a separate pending request; keep it and never block the UI event thread.
    if let Ok(mut pending) = PENDING.lock() {
        if pending.as_deref() == Some(&id) { *pending = None; }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::link_id;
    #[test]
    fn links_carry_exactly_one_opaque_identifier() {
        assert_eq!(link_id("passbook://authorize?requestId=0123456789abcdef0123456789abcdef"), Some("0123456789abcdef0123456789abcdef"));
        for bad in ["passbook://authorize?requestId=short", "passbook://authorize?requestId=0123456789abcdef0123456789abcdef&password=x",
            "passbook://authorize?requestId=0123456789abcdef0123456789abcdef#allow", "https://authorize?requestId=0123456789abcdef0123456789abcdef"] {
            assert_eq!(link_id(bad), None);
        }
    }

    #[cfg(unix)]
    #[test]
    fn cli_output_and_elapsed_time_are_bounded() {
        use super::{bounded_output, Duration, Instant, Zeroizing, Command};
        let mut noisy = Command::new("/bin/sh");
        noisy.args(["-c", "while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; done"]);
        assert!(bounded_output(noisy, Zeroizing::new(Vec::new()), Duration::from_secs(2)).is_err());
        let mut stuck = Command::new("/bin/sh");
        stuck.args(["-c", "while :; do :; done"]);
        let start = Instant::now();
        assert!(bounded_output(stuck, Zeroizing::new(Vec::new()), Duration::from_millis(60)).is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
