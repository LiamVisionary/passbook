// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rizzma, Inc.
// PassBook — a native front end for the credential store this machine shares.
//
// This app deliberately holds no logic of its own. Every question it answers and
// every change it makes goes through the PassBook CLI, which is the same code
// path an app, a script or a terminal uses. Reimplementing any of it in Rust
// would create a second source of truth about who may read what — and the first
// time the two disagreed, the disagreement would be invisible.
//
// It is also not a dependency. Nothing on this machine needs PassBook installed
// to read the store; this is the surface with the strongest guarantees, not a
// gate in front of everything else.
//
// Values never cross this boundary. `passbook state` returns key names, modes,
// unlocks and receipts — the store's contents are read by the process that needs
// them, never by a window someone might be screen-sharing.
//
// Two things do cross it, and it is worth being exact about them rather than
// leaving the sentence above sounding absolute. `reveal_key` returns one value,
// on purpose, because a credential manager that cannot show you your own
// credential is not one. And a vault password travels from the sign-in screen
// to the CLI's stdin, because the sign-in has to happen somewhere and this is
// the window whose job it is. Neither is written down on the way through, and
// neither ever appears in an argument list where `ps` would show it.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::process::Command;

use zeroize::Zeroizing;
use std::sync::OnceLock;

use tauri::{Emitter, Manager};

use serde_json::Value;

/// Where the app's own copy of the CLI lives, learned from Tauri at startup.
///
/// Read through a `OnceLock` rather than threaded through every caller: the
/// resource directory is fixed for the life of the process, and `run` is
/// reached from places that have no `AppHandle` to pass one.
static RESOURCES: OnceLock<PathBuf> = OnceLock::new();

/// The user's home, by whichever name this platform gives it.
///
/// Windows does not set `HOME`. Reading only that name meant the branch below
/// silently became `.local/bin/passbook` — a relative path, matched nothing,
/// and the fallback that was supposed to exist did not.
fn home() -> Option<PathBuf> {
    for name in ["HOME", "USERPROFILE"] {
        if let Ok(value) = std::env::var(name) {
            if !value.is_empty() {
                return Some(PathBuf::from(value));
            }
        }
    }
    None
}

/// The first entry on PATH that names an executable file.
///
/// `Command::new("passbook")` defers this to spawn time, which is fine when
/// there is nothing to fall back to. There is now, so the question has to be
/// answered before choosing.
fn on_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    // On Windows a bare name is resolved through PATHEXT, and the extension
    // that matters here is `.cmd`: that is what the shipped shims are, and
    // Rust will not spawn one without an explicit extension.
    #[cfg(windows)]
    let suffixes: Vec<String> = std::env::var("PATHEXT")
        .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
        .split(';')
        .filter(|part| !part.is_empty())
        .map(|part| part.to_ascii_lowercase())
        .collect();
    #[cfg(not(windows))]
    let suffixes: Vec<String> = vec![String::new()];

    for directory in std::env::split_paths(&path) {
        for suffix in &suffixes {
            let candidate = directory.join(format!("{program}{suffix}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// The Python that runs the bundled modules.
///
/// Windows ships one inside the app, because it is the one platform where
/// assuming a system Python is wrong — and assuming it is exactly how a
/// released build came to open on "program not found".
fn bundled_python(resources: &Path) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let private = resources.join("runtime/python.exe");
        if private.is_file() {
            return Some(private);
        }
    }
    #[cfg(not(windows))]
    {
        // macOS and Linux always have one. Named in falling order of how
        // likely it is to be a real interpreter rather than a stub.
        for name in ["python3", "python"] {
            if let Some(found) = on_path(name) {
                return Some(found);
            }
        }
        let _ = resources;
    }
    None
}

/// The copy of the CLI carried inside this app, if it is there and runnable.
fn bundled_command() -> Option<Command> {
    let resources = RESOURCES.get()?;
    let entry = resources.join("cli/passbook_cli.py");
    if !entry.is_file() {
        return None;
    }
    let python = bundled_python(resources)?;
    let mut command = Command::new(python);
    command.arg(entry);
    // Python writes `__pycache__` next to whatever it imports. Next to these
    // modules is inside the installed app — a directory that is read-only under
    // Program Files, and on macOS is sealed by the notarised signature, which
    // Gatekeeper then rejects on a later launch. Somewhere else, then: still
    // cached, so the window is not recompiling three thousand lines per click.
    command.env("PYTHONPYCACHEPREFIX", std::env::temp_dir().join("passbook-pycache"));
    Some(command)
}

/// Where the CLI lives, best first.
///
/// An explicit `PASSBOOK_CLI` beats everything; then a real install, because
/// somebody who ran setup has a runtime and a store already wired up and the
/// app should use theirs rather than a second one; then the copy inside the
/// app, which is what makes a fresh install work with nothing else present.
fn passbook_command() -> Command {
    if let Ok(explicit) = std::env::var("PASSBOOK_CLI") {
        return Command::new(explicit);
    }
    if let Some(installed) = home().map(|home| home.join(".local/bin/passbook")) {
        if installed.is_file() {
            return Command::new(installed);
        }
    }
    if let Some(found) = on_path("passbook") {
        // A `.cmd` cannot be executed directly; it is a script for the command
        // interpreter, and Rust stopped pretending otherwise in 1.77.
        #[cfg(windows)]
        if found.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("cmd")
            || ext.eq_ignore_ascii_case("bat"))
        {
            let mut command = Command::new("cmd");
            command.arg("/C").arg(found);
            return command;
        }
        return Command::new(found);
    }
    if let Some(bundled) = bundled_command() {
        return bundled;
    }
    // Nothing found. Returning the bare name keeps the failure honest: the
    // error the window shows names the thing that is missing.
    Command::new("passbook")
}

/// Run a PassBook subcommand and return its stdout.
///
/// A failure is returned as an error string rather than swallowed: a management
/// surface that silently shows stale state is worse than one that says it could
/// not reach the thing it manages.
fn run(args: &[&str]) -> Result<String, String> {
    let output = passbook_command()
        .args(args)
        .output()
        .map_err(|error| format!("Could not run PassBook: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail = detail.trim();
        return Err(if detail.is_empty() {
            format!("PassBook exited with status {}", output.status)
        } else {
            detail.to_string()
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// `run`, for the calls whose output is a credential.
///
/// The difference is the whole reason it exists: `run` leaves the value in a
/// `Vec<u8>` from `Command::output`, then in a `String::from_utf8_lossy` copy,
/// then in the `to_string` after it, and none of the three are overwritten when
/// they drop. That was invisible while the value was on its way to the webview
/// — which could not erase anything either — and became worth fixing the moment
/// this side started being the only side that holds it.
///
/// Both intermediates are wrapped, so the bytes are overwritten on the way out
/// whatever this returns.
fn run_secret(args: &[&str]) -> Result<Zeroizing<String>, String> {
    let output = passbook_command()
        .args(args)
        .output()
        .map_err(|error| format!("Could not run PassBook: {error}"))?;
    let stdout = Zeroizing::new(output.stdout);
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail = detail.trim();
        return Err(if detail.is_empty() {
            format!("PassBook exited with status {}", output.status)
        } else {
            detail.to_string()
        });
    }
    Ok(Zeroizing::new(String::from_utf8_lossy(&stdout).trim_end_matches('\n').to_string()))
}

fn run_json(args: &[&str]) -> Result<Value, String> {
    let raw = run(args)?;
    serde_json::from_str(&raw).map_err(|error| format!("PassBook returned something unreadable: {error}"))
}

// ── what the window asks for ───────────────────────────────────────────────

#[tauri::command]
fn state() -> Result<Value, String> {
    run_json(&["state"])
}

#[tauri::command]
fn set_mode(app: String, key: String, mode: String) -> Result<Value, String> {
    let mut args = vec!["policy", "--mode", mode.as_str()];
    if !app.is_empty() {
        args.extend_from_slice(&["--app", app.as_str()]);
    }
    if !key.is_empty() {
        args.extend_from_slice(&["--key", key.as_str()]);
    }
    run(&args)?;
    state()
}

#[tauri::command]
fn unlock(duration: String, reason: String) -> Result<Value, String> {
    run(&["unlock", "--for", duration.as_str(), "--reason", reason.as_str()])?;
    state()
}

#[tauri::command]
fn lock() -> Result<Value, String> {
    // Whatever is on screen was decrypted before the lock and would outlive it
    // by up to the hold. A lock that leaves a readable value behind it is the
    // kind of thing this app has already been wrong about once: the sidebar
    // said "Vault locked" while the eye icon beside every key still worked.
    veil::forget_all();
    run(&["lock"])?;
    state()
}

#[tauri::command]
fn resolve(id: String, approve: bool, remember: String) -> Result<Value, String> {
    let mut args = vec!["approve", id.as_str()];
    if !approve {
        args.push("--deny");
    } else if !remember.is_empty() {
        args.extend_from_slice(&["--for", remember.as_str()]);
    }
    run(&args)?;
    state()
}

#[tauri::command]
fn broker(action: String) -> Result<Value, String> {
    match action.as_str() {
        "start" => run(&["broker", "start"])?,
        "stop" => run(&["broker", "stop"])?,
        _ => return Err("Unknown broker action".into()),
    };
    state()
}

#[tauri::command]
fn revoke(did: String) -> Result<Value, String> {
    run(&["link", "revoke", did.as_str()])?;
    state()
}

/// Adding a key is the one action that carries a secret, so it is passed to the
/// CLI on stdin rather than as an argument — an argument would be visible to
/// `ps` for as long as the process lived.
#[tauri::command]
fn add_key(name: String, value: String, replace: bool) -> Result<Value, String> {
    use std::io::Write;
    use std::process::Stdio;

    if name.trim().is_empty() || value.trim().is_empty() {
        return Err("A key needs a name and a value.".into());
    }
    let mut args = vec!["add", "--stdin"];
    if replace {
        args.push("--replace");
    }
    let mut child = passbook_command()
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("Could not run PassBook: {error}"))?;
    {
        let stdin = child.stdin.as_mut().ok_or("Could not write to PassBook")?;
        writeln!(stdin, "{}={}", name.trim(), value.trim())
            .map_err(|error| format!("Could not write to PassBook: {error}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("PassBook did not finish: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        return Err(detail.trim().to_string());
    }
    state()
}

/// Delete a key from the store.
///
/// The one operation here that can break something else on this machine, so it
/// is its own command rather than a flag on another — and the window asks
/// before calling it.
#[tauri::command]
fn remove_key(name: String) -> Result<Value, String> {
    if name.trim().is_empty() {
        return Err("Which key?".into());
    }
    run(&["remove", name.trim()])?;
    state()
}

/// Show one value — as a picture, and never as a string in the window.
///
/// A credential manager that cannot show you your own credential is not one:
/// you keep keys in order to paste them somewhere eventually. What changed is
/// where "show" happens. This used to return the value, and the window put it
/// in an `<input>`, which meant two things nobody could undo afterwards — the
/// string could not be erased from the JavaScript heap, and its text was
/// published to the platform accessibility tree, where an agent reads it with
/// no screenshot involved. src/veil.rs is the long version.
///
/// So the value stops here. It goes behind a token, the token goes to the
/// window, and the window fetches a PNG of it from the loopback server. The
/// return type is the guarantee, and it is checkable by reading the signature:
/// there is no longer any command in this file that hands a credential to the
/// webview.
///
/// `--confirm` carries the answer to the CLI's own question. `reveal` refuses a
/// caller whose output is being captured — which is what an agent shelling out
/// looks like, and also what this is — so the window has to say that a person
/// asked. It is a hurdle rather than a boundary, exactly as the CLI documents:
/// what actually cannot be revealed is a guarded key, and no flag reaches that.
#[derive(serde::Serialize)]
struct Veiled {
    token: String,
    /// So the window can size the row before the picture arrives, and so a
    /// value that is empty can be said to be empty rather than drawn as
    /// nothing. Character count, not the value.
    length: usize,
    /// How long the window has before the token stops answering.
    hold_ms: u64,
}

#[tauri::command]
fn reveal_key(name: String, px: f32, scale: f32, ink: String) -> Result<Veiled, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Which key?".into());
    }
    if !veil::can_draw() {
        // Fails closed. The alternative — falling back to handing the string to
        // the window — would quietly undo the entire point on exactly the
        // machines least able to notice.
        return Err("This machine has no monospace font PassBook can draw with, \
                    so a value cannot be shown here. Use it instead:  \
                    passbook run -- <command>".into());
    }
    let ask = veil::Ask { px, scale, ink: veil::hex_ink(&ink).unwrap_or([0x16, 0x17, 0x1a]) };

    // Where the drawing happens depends on what this machine promises.
    //
    // A machine that seals reads has said values go only into processes the
    // broker started. This one was not, so it must not hold the plaintext even
    // for a moment — the drawing is done by a child the broker spawns, and what
    // comes back here is pixels. On a machine that has not sealed reads there
    // is nothing to honour and the extra process would only be ceremony, so the
    // value is read and drawn here and dropped on the next line.
    let (picture, length) = if sealed_reads() {
        draw_through_broker(name, &ask)?
    } else {
        let value = run_secret(&["reveal", name, "--confirm", name])?;
        (veil::draw(&value, &ask)?, value.chars().count())
    };

    Ok(Veiled {
        token: veil::hold(picture),
        length,
        hold_ms: veil::HOLD.as_millis() as u64,
    })
}

/// Whether this machine hands values to callers the broker did not start.
///
/// Cached for a few seconds, because it sat on the hot path: asking the CLI
/// costs a Python start and a broker round trip — 47ms measured — and the
/// window paid it before every single reveal, on top of the reveal itself.
///
/// Caching a policy answer is only safe because this one is not a boundary. It
/// picks which *path* the app takes, and both paths end somewhere the CLI
/// decides again: guess "open" on a sealed machine and `reveal` is refused with
/// a reason; guess "sealed" on an open one and the brokered draw works anyway.
/// The seal is enforced where it always was, and this is a hint about which
/// door to knock on.
fn sealed_reads() -> bool {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    const FRESH: Duration = Duration::from_secs(5);
    static SEEN: Mutex<Option<(bool, Instant)>> = Mutex::new(None);

    let mut seen = SEEN.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((answer, at)) = *seen {
        if at.elapsed() < FRESH {
            return answer;
        }
    }
    let answer = run(&["grants"]).map(|out| out.contains("reads: sealed")).unwrap_or(false);
    *seen = Some((answer, Instant::now()));
    answer
}

/// Draw a credential in a process the broker started, and read back the picture.
///
/// The child is this same binary in `--draw` mode. It is given the value the way
/// every other brokered child is — in its environment, by `passbook run` — and
/// it writes a PNG to a path this side chose. Nothing is written to its stdout,
/// deliberately: `passbook run` pumps a child's output through a redactor that
/// decodes it as UTF-8 with replacement, so a PNG sent that way would arrive
/// with every non-UTF-8 byte replaced. The file is the only clean channel, and
/// it holds pixels rather than a credential.
fn draw_through_broker(name: &str, ask: &veil::Ask) -> Result<(Vec<u8>, usize), String> {
    let out = veil::scratch_path(name)?;
    let me = std::env::current_exe()
        .map_err(|error| format!("PassBook could not find its own binary: {error}"))?;
    let ink = ask.ink.iter().map(|byte| format!("{byte:02x}")).collect::<String>();

    let status = passbook_command()
        .args(["run", "--only", name, "--app", "passbook-app", "--"])
        .arg(&me)
        .arg("--draw")
        .args([name, &out.to_string_lossy(), &ask.px.to_string(), &ask.scale.to_string(), &ink])
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|error| format!("Could not run PassBook: {error}"))?;

    let picture = std::fs::read(&out);
    // Gone before this returns, whether or not it was readable. A picture of a
    // credential is not something to leave lying in a temp directory because an
    // error path forgot about it.
    let _ = std::fs::remove_file(&out);

    let picture = picture.map_err(|_| {
        let detail = String::from_utf8_lossy(&status.stderr);
        let detail = detail.trim();
        if detail.is_empty() {
            "PassBook could not draw that value.".to_string()
        } else {
            detail.to_string()
        }
    })?;
    // The length is not knowable on this side any more, and inventing one would
    // be worse than saying so: the window uses it only to tell an empty value
    // from a drawn one, and an empty value draws an empty file.
    let length = if picture.is_empty() { 0 } else { 1 };
    if picture.is_empty() {
        return Err("That value is empty.".into());
    }
    Ok((picture, length))
}

/// `--draw KEY OUT PX SCALE INK` — this binary, as the child of a broker.
///
/// Reads the value out of the environment the broker put it there, draws it,
/// writes the PNG, and prints nothing. It never opens a window and never talks
/// to the store: everything it is allowed to have already arrived in its env.
///
/// Returns whether this was a draw run, so `main` can leave before Tauri starts.
fn drew() -> bool {
    let argv: Vec<String> = std::env::args().collect();
    let Some(at) = argv.iter().position(|a| a == "--draw") else { return false };
    let rest = &argv[at + 1..];
    if rest.len() < 5 {
        eprintln!("--draw needs KEY OUT PX SCALE INK");
        std::process::exit(2);
    }
    let (key, out) = (&rest[0], &rest[1]);
    let ask = veil::Ask {
        px: rest[2].parse().unwrap_or(12.0),
        scale: rest[3].parse().unwrap_or(1.0),
        ink: veil::hex_ink(&rest[4]).unwrap_or([0x16, 0x17, 0x1a]),
    };
    let value = Zeroizing::new(std::env::var(key).unwrap_or_default());
    if value.is_empty() {
        // An empty file is how the parent is told the value was empty. Exiting
        // non-zero here would be reported to the person as a failure to draw.
        let _ = std::fs::write(out, b"");
        std::process::exit(0);
    }
    match veil::draw(&value, &ask) {
        Ok(png) => {
            if let Err(error) = veil::write_private(out, &png) {
                eprintln!("{error}");
                std::process::exit(1);
            }
            std::process::exit(0);
        }
        Err(why) => {
            eprintln!("{why}");
            std::process::exit(1);
        }
    }
}

/// What this platform actually gave the window, for the window to say so.
///
/// Two of the three protections are conditional — capture exclusion does not
/// exist on Linux, and drawing needs a font this machine might not have — and
/// a UI that claimed them unconditionally would be lying on exactly the
/// machines where it mattered. So the window asks rather than assumes.
#[derive(serde::Serialize)]
struct Protection {
    /// `NSWindowSharingType::None` / `WDA_EXCLUDEFROMCAPTURE`. Compile-time:
    /// tao implements this on macOS and Windows and compiles it out elsewhere.
    capture: bool,
    /// Whether a value can be drawn at all on this machine.
    drawing: bool,
}

#[tauri::command]
fn capture_protection() -> Protection {
    Protection {
        capture: cfg!(any(target_os = "macos", target_os = "windows")),
        drawing: veil::can_draw(),
    }
}

/// Forget a revealed value now, rather than when its hold runs out.
///
/// The window calls this when the eye is clicked again, when its own auto-hide
/// fires, and when the row goes away. None of those are load-bearing — the hold
/// in veil.rs expires regardless — but a value that is on screen for four
/// seconds should not sit in this process for forty-five.
#[tauri::command]
fn forget_reveal(token: String) -> bool {
    veil::forget(&token)
}

/// Put one value on the clipboard, without it passing through the window.
///
/// `navigator.clipboard.writeText` takes a string, so copy was the one path
/// that re-materialised in JavaScript everything the veil avoids — and it did
/// it on the row's most-used button. The value goes from the CLI to the
/// platform clipboard inside this process.
///
/// The clipboard itself is still the clipboard: every process on this machine
/// can read it, and on macOS it goes to the user's other devices. Nothing here
/// changes that, and it would be dishonest to imply otherwise. What changes is
/// that pressing copy no longer also leaves an unerasable copy in the webview.
#[tauri::command]
fn copy_key(app: tauri::AppHandle, name: String) -> Result<(), String> {
    use tauri_plugin_clipboard_manager::ClipboardExt;

    let name = name.trim();
    if name.is_empty() {
        return Err("Which key?".into());
    }
    // A sealed machine does not put a credential on the clipboard, and saying
    // so is more honest than the alternative. The clipboard is readable by
    // every process on this machine and, on macOS, by this person's other
    // devices — so "values go only into processes the broker started" and "here
    // it is on the pasteboard" cannot both be true.
    if sealed_reads() {
        return Err("This machine does not copy credential values. \
                    Run what needs it instead:  passbook run -- <command>".into());
    }
    let value = run_secret(&["reveal", name, "--confirm", name])?;
    app.clipboard()
        .write_text(value.as_str())
        .map_err(|error| format!("Could not reach the clipboard: {error}"))
}

// ── sign-ins ───────────────────────────────────────────────────────────────
//
// An OAuth grant is a credential with a clock on it. The window shows whether
// each one is still live and can renew or forget one; connecting opens a
// browser, so it is spawned rather than awaited — a Tauri command that blocked
// for three minutes waiting on a person would freeze the window.

#[tauri::command]
fn oauth_state() -> Result<Value, String> {
    run_json(&["oauth", "--json"])
}

#[tauri::command]
fn oauth_refresh(id: String) -> Result<Value, String> {
    if id.trim().is_empty() {
        return Err("Which sign-in?".into());
    }
    run(&["oauth", "refresh", id.trim()])?;
    oauth_state()
}

#[tauri::command]
fn oauth_disconnect(id: String) -> Result<Value, String> {
    if id.trim().is_empty() {
        return Err("Which sign-in?".into());
    }
    run(&["oauth", "remove", id.trim(), "--yes"])?;
    oauth_state()
}

/// Start a browser sign-in. Returns as soon as it is running; the window polls
/// `oauth_state` to find out how it went.
#[tauri::command]
fn oauth_connect(id: String) -> Result<Value, String> {
    use std::process::Stdio;

    if id.trim().is_empty() {
        return Err("Which sign-in?".into());
    }
    passbook_command()
        .args(["oauth", "connect", id.trim()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("Could not start the sign-in: {error}"))?;
    Ok(Value::Bool(true))
}

// ── organising the store: groups, audiences, the matrix ────────────────────
//
// These change who can read what, so they go through the same CLI every other
// surface uses rather than editing the policy file directly. A second writer
// with its own idea of the format is how two surfaces start disagreeing about
// who has access.

/// Pin keys to a group. An empty group returns them to inference from the name.
#[tauri::command]
fn set_key_group(group: String, names: Vec<String>) -> Result<Value, String> {
    if names.is_empty() {
        return Err("Which keys?".into());
    }
    let mut args: Vec<&str> = vec!["group", "set", group.trim()];
    for name in &names {
        args.push(name.trim());
    }
    run(&args)?;
    state()
}

/// Set the reach of several keys at once.
///
/// The CLI loops and reports per key, so one key owned by another workspace
/// refuses without stopping the rest — and its refusal comes back verbatim,
/// because "denied" with no cause is what makes people stop using a control.
#[tauri::command]
fn set_keys_scope(names: Vec<String>, scope: String) -> Result<Value, String> {
    if names.is_empty() {
        return Err("Nothing selected.".into());
    }
    let flag = match scope.as_str() {
        "workspace" => "--workspace",
        "machine" => "--machine",
        "tailnet" => "--tailnet",
        other => return Err(format!("unknown scope: {other}")),
    };
    let mut args: Vec<&str> = vec!["scope", "set"];
    for name in &names {
        args.push(name.trim());
    }
    args.push(flag);
    // A partial refusal is not a failure of the whole action: whatever changed
    // has changed, and the window needs the new state either way.
    let outcome = run(&args);
    let refreshed = state()?;
    match outcome {
        Ok(_) => Ok(refreshed),
        Err(detail) => Ok(serde_json::json!({ "state": refreshed, "partial": detail })),
    }
}

/// Delete several keys at once. The window asks first.
#[tauri::command]
fn remove_keys(names: Vec<String>) -> Result<Value, String> {
    if names.is_empty() {
        return Err("Nothing selected.".into());
    }
    let mut args: Vec<&str> = vec!["remove"];
    for name in &names {
        args.push(name.trim());
    }
    run(&args)?;
    state()
}

/// How far a key reaches: this workspace, the machine, or the tailnet.
///
/// The CLI refuses when this workspace does not own the key, and that refusal is
/// shown verbatim rather than softened — "only the acme workspace can change
/// this" is the whole answer, and rewording it would lose which workspace to go
/// and ask.
#[tauri::command]
fn set_key_scope(name: String, scope: String) -> Result<Value, String> {
    if name.trim().is_empty() {
        return Err("Which key?".into());
    }
    let flag = match scope.as_str() {
        "workspace" => "--workspace",
        "machine" => "--machine",
        "tailnet" => "--tailnet",
        other => return Err(format!("unknown scope: {other}")),
    };
    run(&["scope", "set", name.trim(), flag])?;
    state()
}

/// Say who a key is for: everyone, only these apps, or everyone except these.
///
/// The verb stays `agents` even though the CLI now calls it `apps`: `agents` is
/// an alias on the new CLI and the only name on an older one, and the app is
/// routinely newer than the `passbook` it shells out to.
#[tauri::command]
fn set_key_audience(name: String, mode: String, agents: Vec<String>) -> Result<Value, String> {
    if name.trim().is_empty() {
        return Err("Which key?".into());
    }
    let mut args: Vec<&str> = vec!["agents", "set", name.trim()];
    match mode.as_str() {
        "all" => args.push("--everyone"),
        "include" => args.push("--only"),
        "exclude" => args.push("--block"),
        other => return Err(format!("unknown audience: {other}")),
    }
    if mode != "all" {
        if agents.is_empty() {
            return Err("Name at least one app.".into());
        }
        for agent in &agents {
            args.push(agent.trim());
        }
    }
    run(&args)?;
    state()
}

/// Which apps can read which keys. Fetched on demand: a full grid over a
/// large store is not something to ship with every background refresh.
///
/// `--agent` for the same reason as above: `--app` is the new spelling, this
/// one works on every CLI that has ever shipped.
#[tauri::command]
fn access_matrix(agents: Vec<String>) -> Result<Value, String> {
    let mut args: Vec<&str> = vec!["matrix", "--json"];
    if !agents.is_empty() {
        args.push("--agent");
        for agent in &agents {
            args.push(agent.trim());
        }
    }
    run_json(&args)
}

// ── the vault: profiles, sign-in, and sealing ──────────────────────────────
//
// A sealed store is unreadable until somebody signs in, so these are the
// commands that decide whether this machine has any credentials at all right
// now. The password reaches the CLI on stdin and nowhere else — never as an
// argument, which every process listing on the machine can read.

fn run_with_password(args: &[&str], password: &str) -> Result<String, String> {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = passbook_command()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("Could not run PassBook: {error}"))?;
    {
        let stdin = child.stdin.as_mut().ok_or("Could not write to PassBook")?;
        writeln!(stdin, "{password}").map_err(|error| format!("Could not write to PassBook: {error}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("PassBook did not finish: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail = detail.trim();
        return Err(if detail.is_empty() {
            "That did not open the vault.".to_string()
        } else {
            detail.to_string()
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Everything a sign-in screen needs: locked or open, and who could open it.
#[tauri::command]
fn vault_state() -> Result<Value, String> {
    run_json(&["vault", "--json"])
}

/// Open the vault. An empty `duration` takes the CLI's default, which is a
/// session that lasts until somebody locks it — agents read credentials at
/// four in the morning, and a vault that closes itself overnight does not
/// protect anything, it just stops the work.
#[tauri::command]
fn vault_signin(
    profile: String,
    password: String,
    duration: String,
    workspace: String,
) -> Result<Value, String> {
    if password.is_empty() {
        return Err("Enter your vault password.".into());
    }
    // The broker is what holds the opened vault, so there has to be one.
    let _ = run(&["broker", "start"]);
    let mut args = vec!["signin", "--password-stdin"];
    if !profile.trim().is_empty() {
        args.push("--profile");
        args.push(profile.trim());
    }
    if !workspace.trim().is_empty() {
        args.push("--workspace");
        args.push(workspace.trim());
    }
    if !duration.trim().is_empty() {
        args.push("--for");
        args.push(duration.trim());
    }
    run_with_password(&args, &password)?;
    vault_state()
}

/// Wrap a workspace's data key with a passkey's PRF output.
///
/// The WebAuthn ceremony happens in the window, because that is the only place
/// with an authenticator; the secret it returns crosses one pipe and is used
/// once. It is never stored — storing it would make the ceremony decorative.
#[tauri::command]
fn vault_add_passkey(
    workspace: String,
    credential_id: String,
    prf_secret: String,
    label: String,
    rp_id: String,
    password: String,
) -> Result<Value, String> {
    if credential_id.trim().is_empty() || prf_secret.trim().is_empty() {
        return Err("That passkey returned nothing to wrap the key with.".into());
    }
    if password.is_empty() {
        return Err("The vault password is needed once, to wrap the key.".into());
    }
    let mut args = vec![
        "passkey", "enrol",
        "--credential-id", credential_id.trim(),
        "--label", if label.trim().is_empty() { "This device" } else { label.trim() },
        "--password-stdin",
    ];
    if !rp_id.trim().is_empty() {
        args.push("--rp-id");
        args.push(rp_id.trim());
    }
    if !workspace.trim().is_empty() {
        args.push("--workspace");
        args.push(workspace.trim());
    }
    // The PRF secret first, then the password — the order `passkey enrol` reads
    // them in. Both leave this process on stdin and neither is ever an argv.
    let feed = format!("{}\n{}", prf_secret.trim(), password);
    run_with_password(&args, &feed)?;
    vault_state()
}

/// Open the vault with a passkey the window has just exercised.
///
/// The lock screen has offered "Unlock with passkey" since the gate was built
/// and nothing was listening: the button had no handler, and there was no
/// command for one to call. It did not look broken, which is the worst way for
/// a control on a lock screen to be broken.
///
/// The PRF secret goes over stdin exactly as enrolment sends it. It is a key,
/// not a name, and an argv is readable by anything on this machine.
#[tauri::command]
fn vault_signin_passkey(
    workspace: String,
    credential_id: String,
    prf_secret: String,
    duration: String,
) -> Result<Value, String> {
    if credential_id.trim().is_empty() || prf_secret.trim().is_empty() {
        return Err("That passkey returned nothing to open the vault with.".into());
    }
    let wanted = if duration.trim().is_empty() { "always" } else { duration.trim() };
    let mut args = vec!["signin", "--passkey", credential_id.trim(), "--for", wanted];
    if !workspace.trim().is_empty() {
        args.push("--workspace");
        args.push(workspace.trim());
    }
    run_with_password(&args, prf_secret.trim())?;
    vault_state()
}

/// Whether this device can verify its owner, and what to call it.
///
/// Asked before anything is drawn, so the window never offers a button that
/// cannot work — which is exactly what "Add a passkey" was doing.
#[tauri::command]
fn biometric_status() -> Value {
    let status = passbook_biometric::status();
    serde_json::json!({
        "available": status.available,
        "kind": status.kind.map(|kind| kind.as_str()),
        "label": status.kind.map(|kind| kind.label()),
    })
}

/// Open the vault with Touch ID.
///
/// Two steps, and the order matters. The device factor already exists in this
/// store — `passbook profile trust-device` puts a wrapped key in the OS
/// keystore, and `passbook signin --device` opens the vault with it. What was
/// missing is a person in that sequence: the keystore item carries no
/// biometric guard, because it is written by a plain interpreter and only a
/// signed bundle can create a guarded one. This app is a signed bundle, so it
/// asks first and signs in only on a yes.
///
/// Be exact about what that buys. It is a lock on the window, not on the key:
/// anything already running as you can call `passbook signin --device` itself
/// and never see a prompt. It stops somebody at your keyboard, which is what
/// it is for.
#[tauri::command]
async fn vault_signin_device(workspace: String) -> Result<Value, String> {
    let asking = if workspace.trim().is_empty() {
        "unlock PassBook".to_string()
    } else {
        format!("unlock the {} workspace in PassBook", workspace.trim())
    };
    tauri::async_runtime::spawn_blocking(move || passbook_biometric::authenticate(&asking))
        .await
        .map_err(|error| format!("Could not wait for {error}"))??;

    let mut args = vec!["signin", "--device"];
    if !workspace.trim().is_empty() {
        args.push("--workspace");
        args.push(workspace.trim());
    }
    run(&args)?;
    vault_state()
}

/// Let this device open the vault, after proving somebody is here.
///
/// The password is needed once, to wrap the key for the keystore. It goes over
/// stdin like every other password in this file, never an argv.
#[tauri::command]
async fn vault_trust_device(password: String) -> Result<Value, String> {
    if password.is_empty() {
        return Err("The vault password is needed once, to wrap the key.".into());
    }
    tauri::async_runtime::spawn_blocking(|| {
        passbook_biometric::authenticate("let this device open PassBook")
    })
    .await
    .map_err(|error| format!("Could not wait for {error}"))??;
    run_with_password(&["profile", "trust-device", "--yes", "--password-stdin"], &password)?;
    vault_state()
}

/// Give a workspace a key of its own, and open it.
///
/// A workspace was always a separate store; until now one vault at the machine
/// root opened all of them, so "which workspace" and "whose key" were separate
/// questions. Creating one here is what makes them the same question: its own
/// library, its own key.
#[tauri::command]
fn vault_create_workspace(name: String, password: String) -> Result<Value, String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Give the workspace a name.".into());
    }
    if password.chars().count() < 8 {
        return Err("A vault password must be at least 8 characters.".into());
    }
    let _ = run(&["broker", "start"]);
    run_with_password(
        &["profile", "create", "Owner", "--use", "--workspace", name.as_str(),
          "--password-stdin"],
        &password,
    )?;
    vault_state()
}

/// Close agent access. Not the same button as locking the window.
///
/// Locking the window is a decision about who is at the keyboard; this is a
/// decision about what runs while nobody is. They were one button, so putting
/// the app away at the end of the day also stopped every agent reading
/// credentials overnight — and the way people work around that is to never
/// lock anything.
#[tauri::command]
fn vault_signout(workspace: String, everything: bool) -> Result<Value, String> {
    veil::forget_all();
    let mut args = vec!["signout"];
    if everything {
        args.push("--all");
    } else if !workspace.trim().is_empty() {
        args.push("--workspace");
        args.push(workspace.trim());
    }
    run(&args)?;
    vault_state()
}

#[tauri::command]
fn vault_create_profile(label: String, password: String) -> Result<Value, String> {
    if label.trim().is_empty() {
        return Err("Give the profile a name.".into());
    }
    if password.chars().count() < 8 {
        return Err("A vault password must be at least 8 characters.".into());
    }
    run_with_password(&["profile", "create", label.trim(), "--password-stdin"], &password)?;
    vault_state()
}

#[tauri::command]
fn vault_use_profile(label: String) -> Result<Value, String> {
    if label.trim().is_empty() {
        return Err("Which profile?".into());
    }
    run(&["profile", "use", label.trim()])?;
    vault_state()
}

/// Turn one change-confirmation on or off.
#[tauri::command]
fn set_confirmation(op: String, required: bool) -> Result<Value, String> {
    let op = op.trim();
    if !["add", "modify", "delete"].contains(&op) {
        return Err(format!("{op} is not a change that can be confirmed"));
    }
    let mut args: Vec<&str> = vec!["confirm", op];
    if !required {
        args.push("--off");
    }
    run(&args)?;
    state()
}

/// Which projects a key is for: every one, only these, or all but these.
#[tauri::command]
fn set_key_projects(name: String, mode: String, projects: Vec<String>) -> Result<Value, String> {
    if name.trim().is_empty() {
        return Err("Which key?".into());
    }
    let mut args: Vec<&str> = vec!["projects", "set", name.trim()];
    match mode.as_str() {
        "all" => args.push("--every"),
        "include" => args.push("--only"),
        "exclude" => args.push("--without"),
        other => return Err(format!("{other} is not a project rule")),
    }
    let named: Vec<String> = projects
        .iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    if mode != "all" && named.is_empty() {
        return Err("Pick at least one project.".into());
    }
    for project in &named {
        args.push(project);
    }
    run(&args)?;
    state()
}

/// Write the store to a file the person picked in a save dialog.
///
/// The passphrase travels to the CLI's stdin like a vault password does, and
/// the values never enter this process: the CLI opens them, encrypts them and
/// writes the file. This side only ever sees a path and a count.
#[tauri::command]
fn export_store(path: String, shape: String, passphrase: String, note: String) -> Result<Value, String> {
    if path.trim().is_empty() {
        return Err("Where should it go?".into());
    }
    let target = path.trim();
    let mut args: Vec<&str> = vec!["export", target];
    match shape.as_str() {
        "plain" => {
            args.push("--plain");
            args.push("--i-understand");
        }
        "gpg" => args.push("--gpg"),
        _ => {}
    }
    if !note.trim().is_empty() {
        args.push("--note");
        args.push(note.trim());
    }
    if shape == "plain" {
        run(&args)?;
    } else {
        if passphrase.chars().count() < 8 {
            return Err("An export passphrase must be at least 8 characters.".into());
        }
        args.push("--password-stdin");
        run_with_password(&args, &passphrase)?;
    }
    Ok(serde_json::json!({ "ok": true, "path": target, "shape": shape }))
}

/// Look inside an export without importing it.
#[tauri::command]
fn inspect_export(path: String, passphrase: String) -> Result<Value, String> {
    if path.trim().is_empty() {
        return Err("Which file?".into());
    }
    let target = path.trim();
    let args: Vec<&str> = vec!["import", target, "--dry-run", "--password-stdin"];
    let detail = run_with_password(&args, &passphrase)?;
    Ok(serde_json::json!({ "ok": true, "detail": detail }))
}

/// Read an export into this store.
#[tauri::command]
fn import_store(path: String, passphrase: String, overwrite: bool) -> Result<Value, String> {
    if path.trim().is_empty() {
        return Err("Which file?".into());
    }
    let target = path.trim();
    let mut args: Vec<&str> = vec!["import", target, "--password-stdin"];
    if overwrite {
        args.push("--overwrite");
    }
    let detail = run_with_password(&args, &passphrase)?;
    let next = state()?;
    Ok(serde_json::json!({ "ok": true, "detail": detail, "state": next }))
}

/// Mint a recovery code. Returned once, to be written down.
#[tauri::command]
fn make_recovery_code(password: String) -> Result<Value, String> {
    if password.is_empty() {
        return Err("The vault password is needed to mint a recovery code.".into());
    }
    let detail = run_with_password(&["recovery", "--password-stdin"], &password)?;
    // The CLI prints the code inside a sentence; the window wants just the code.
    let code = detail
        .lines()
        .map(str::trim)
        .find(|line| line.len() >= 29 && line.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        .unwrap_or("")
        .to_string();
    if code.is_empty() {
        return Err("A recovery code was made, but this window could not read it back. \
                    Run `passbook recovery` in a terminal instead.".into());
    }
    Ok(serde_json::json!({ "ok": true, "code": code }))
}

/// Stop counting a tailnet machine as holding this store.
#[tauri::command]
fn forget_machine(host: String) -> Result<Value, String> {
    if host.trim().is_empty() {
        return Err("Which machine?".into());
    }
    run(&["forget", host.trim()])?;
    state()
}

/// Switch which workspace this machine acts for.
///
/// Written into HivemindOS's own manifest by the CLI, not a PassBook-side copy,
/// so the two apps cannot disagree about which workspace is active.
#[tauri::command]
fn set_workspace(name: String) -> Result<Value, String> {
    if name.trim().is_empty() {
        return Err("Which workspace?".into());
    }
    run(&["workspace", "use", name.trim()])?;
    state()
}

/// Profile, seal, broker and sign-in in one go — the whole first run.
///
/// These four are never useful apart, and asking for the same password four
/// times is how a security feature earns a reputation for being annoying. The
/// window offered them as separate steps and there was no single action that
/// secured a machine, which is exactly the thing a first-run screen is for.
#[tauri::command]
fn vault_secure(label: String, password: String) -> Result<Value, String> {
    if password.chars().count() < 8 {
        return Err("A vault password must be at least 8 characters.".into());
    }
    let name = if label.trim().is_empty() { "Owner" } else { label.trim() };
    run_with_password(&["secure", "--profile-name", name, "--password-stdin"], &password)?;
    vault_state()
}

/// Encrypt every readable value. The action that makes the app's warning go away.
#[tauri::command]
fn vault_seal(password: String) -> Result<Value, String> {
    if password.is_empty() {
        return Err("Enter your vault password.".into());
    }
    run_with_password(&["seal", "--password-stdin"], &password)?;
    vault_state()
}

/// Put it all back. Offered next to sealing so the door out is as visible as
/// the door in — a security feature nobody can reverse is one nobody turns on.
#[tauri::command]
fn vault_unseal(password: String) -> Result<Value, String> {
    if password.is_empty() {
        return Err("Enter your vault password.".into());
    }
    run_with_password(&["unseal", "--password-stdin"], &password)?;
    vault_state()
}

/// What the record holds about one key, proofs included.
///
/// Re-hash the whole access record and say whether the chain holds.
///
/// On demand, for the same reason `key_history` is. This walks every row and
/// recomputes its hash, which on a six-megabyte ledger is the most expensive
/// thing the CLI does — and `state` runs every five seconds behind an open
/// window. Verifying twelve times a minute is not what makes a ledger
/// trustworthy; it is just the bill for a page nobody had open.
#[tauri::command]
fn verify_record() -> Result<Value, String> {
    let full = run_json(&["state", "--verify"])?;
    Ok(full.get("record").cloned().unwrap_or(Value::Null))
}

/// Fetched on demand rather than shipped with every state refresh: a store of
/// several hundred keys would otherwise carry a history nobody asked to see.
#[tauri::command]
fn key_history(name: String) -> Result<Value, String> {
    if name.trim().is_empty() {
        return Err("Which key?".into());
    }
    run_json(&["history", name.trim(), "--json", "--limit", "60"])
}

/// The window's own web server, and why a credential app runs one.
///
/// Tauri serves a window from its own scheme, `tauri://localhost`. That is
/// fine for everything except one thing: a passkey is bound to a domain, and a
/// custom scheme has none, so WebAuthn refuses the ceremony before anything is
/// drawn. Measured here: an origin with no domain in it comes back in about a
/// millisecond with SecurityError "This is an invalid domain", while
/// `http://localhost` starts the ceremony and waits on the authenticator.
///
/// So the window is served over `http://localhost` on a loopback port instead.
/// This is the same shape HivemindOS's desktop app ends up with — its embedded
/// Next server means its webview is already on an http origin — and it needs
/// no entitlement of any kind. What it does need is the matching grant in
/// `capabilities/default.json`, because Tauri will not expose IPC to a page it
/// did not serve itself.
///
/// Only the two files that make up the window are served, only to loopback,
/// and only to a request that asked for this host. They contain no credential:
/// the store is read over IPC by the process that needs it, never over this.
mod ask;
mod veil;

mod ui {
    use std::io::{Read, Write};
    use std::sync::OnceLock;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};

    const INDEX: &[u8] = include_bytes!("../../ui/index.html");
    const MARK: &[u8] = include_bytes!("../../ui/mark.png");

    /// The port this window prefers, and why it is not simply left to the OS.
    ///
    /// An origin includes its port, and the window remembers whether it is
    /// locked in storage scoped to that origin. A port the OS picks fresh each
    /// launch would therefore forget the lock every time the app restarted —
    /// quietly, which is the worst way for a lock to fail. So a fixed port is
    /// asked for first, and the neighbours after it, before giving up and
    /// letting the OS choose.
    pub const PREFERRED_PORT: u16 = 17817;
    pub const NEIGHBOURS: u16 = 8;

    /// Bind loopback and answer on it until the app quits.
    pub fn serve() -> std::io::Result<u16> {
        let mut listener = None;
        for candidate in PREFERRED_PORT..PREFERRED_PORT.saturating_add(NEIGHBOURS) {
            if let Ok(bound) = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, candidate))) {
                listener = Some(bound);
                break;
            }
        }
        let listener = match listener {
            Some(bound) => bound,
            // Every one of them taken is not a reason not to start. The window
            // works; it just will not remember a lock across a restart, and it
            // is told so rather than left to find out.
            None => TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?,
        };
        let port = listener.local_addr()?.port();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let _ = answer(stream);
                });
            }
        });
        Ok(port)
    }

    /// What to do with a request a page posted. Set once, by `main`.
    ///
    /// The server lives in here and knows nothing about vaults; this is the
    /// one seam between "bytes arrived on a socket" and "a person is asked".
    pub static ON_ASK: OnceLock<Box<dyn Fn(&str, &str) -> Result<(), String> + Send + Sync>> =
        OnceLock::new();

    /// A request body is a credential list. Big enough for 25 of them, small
    /// enough that nothing can be parked in this process's memory.
    const MAX_BODY: usize = 64 * 1024;

    fn header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
        request.split("\r\n").skip(1).find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }

    fn answer(mut stream: TcpStream) -> std::io::Result<()> {
        // Read until the headers are complete rather than taking one fixed
        // bite: a POST body arrives behind them and can span reads.
        let mut raw: Vec<u8> = Vec::with_capacity(4096);
        let mut chunk = [0u8; 2048];
        let head_end = loop {
            let read = stream.read(&mut chunk)?;
            if read == 0 {
                break None;
            }
            raw.extend_from_slice(&chunk[..read]);
            if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                break Some(at + 4);
            }
            if raw.len() > MAX_BODY {
                break None;
            }
        };
        let Some(head_end) = head_end else {
            return send(&mut stream, "400 Bad Request", "text/plain", b"no", false);
        };
        let request = String::from_utf8_lossy(&raw[..head_end]).into_owned();
        let start = request.split("\r\n").next().unwrap_or("");
        let mut parts = start.split(' ');
        let method = parts.next().unwrap_or("");
        let target = parts.next().unwrap_or("/");
        let (path, query) = target.split_once('?').unwrap_or((target, ""));

        // A page fetched under some other name is not this window's page, and
        // the Host is what decides the origin a passkey would be bound to.
        let host_ok = header(&request, "host").is_some_and(|value| {
            let name = value.split(':').next().unwrap_or("");
            name == "localhost" || name == "127.0.0.1"
        });
        if !host_ok {
            return send(&mut stream, "400 Bad Request", "text/plain", b"no", false);
        }

        // The handover endpoint. A button on somebody else's documentation
        // posts here, so it has to be reachable cross-origin — which is safe
        // only because nothing here stores anything. It parks a request for a
        // person to look at, and that person is the entire access control.
        if path == "/ask" {
            if method == "OPTIONS" {
                return send_cors(&mut stream, "204 No Content", b"");
            }
            if method != "POST" {
                return send_cors(&mut stream, "405 Method Not Allowed", b"post here");
            }
            let length: usize = header(&request, "content-length")
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            if length > MAX_BODY {
                return send_cors(&mut stream, "413 Payload Too Large", b"too much");
            }
            let mut body: Vec<u8> = raw[head_end..].to_vec();
            while body.len() < length {
                let read = stream.read(&mut chunk)?;
                if read == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..read]);
            }
            body.truncate(length);
            let origin = header(&request, "origin").unwrap_or("").to_string();
            let text = String::from_utf8_lossy(&body).into_owned();
            let answered = match ON_ASK.get() {
                Some(handler) => handler(&text, &origin),
                None => Err("PassBook is still starting up.".into()),
            };
            return match answered {
                Ok(()) => send_cors(&mut stream, "202 Accepted", br#"{"ok":true}"#),
                // The reason goes back so the page can tell the person
                // something better than "it did not work".
                Err(reason) => {
                    let body = serde_json::json!({ "ok": false, "error": reason }).to_string();
                    send_cors(&mut stream, "400 Bad Request", body.as_bytes())
                }
            };
        }

        if method != "GET" && method != "HEAD" {
            return send(&mut stream, "400 Bad Request", "text/plain", b"no", false);
        }

        // A revealed credential, as a picture. The token is the whole of the
        // authorisation: 256 bits from the OS, held for `veil::HOLD`, and known
        // only to the window that asked for it.
        //
        // This route is the one thing on this server that answers with
        // something derived from a secret, so unlike `/ask` it is deliberately
        // *not* reachable cross-origin. `send` sets no CORS headers, which
        // stops a page in the browser reading the bytes back; the check below
        // stops it loading them at all where the engine says where it came
        // from. Neither is load-bearing on its own — a page that cannot guess
        // the token has nothing to ask for — and both are here because the cost
        // is two lines.
        if path == "/veil" {
            let cross = header(&request, "sec-fetch-site")
                .is_some_and(|site| site.trim().eq_ignore_ascii_case("cross-site"));
            if cross {
                return send(&mut stream, "403 Forbidden", "text/plain", b"no", false);
            }
            let token = query.split('&').find_map(|pair| {
                let (key, value) = pair.split_once('=')?;
                (key == "t").then(|| value.to_string())
            }).unwrap_or_default();
            // Size and colour were settled when the value was revealed, because
            // that is the moment the plaintext existed. This only hands back
            // what was drawn then.
            return match crate::veil::picture(&token) {
                Some(png) => send(&mut stream, "200 OK", "image/png", &png, method == "HEAD"),
                // The hold ended, or that token was never real. The window
                // treats both the same way — it stops showing the row as
                // revealed — so they answer the same way here.
                None => send(&mut stream, "404 Not Found", "text/plain", b"not here", false),
            };
        }

        let (status, kind, body): (&str, &str, &[u8]) = match path {
            "/" | "/index.html" => ("200 OK", "text/html; charset=utf-8", INDEX),
            "/mark.png" => ("200 OK", "image/png", MARK),
            _ => ("404 Not Found", "text/plain", b"not here"),
        };
        send(&mut stream, status, kind, body, method == "HEAD")
    }

    /// The handover reply. `*` rather than an echoed origin because there are
    /// no cookies and no credentials on this endpoint: the reply says only
    /// whether a request was parked, and reading that tells a page nothing it
    /// did not already know.
    fn send_cors(stream: &mut TcpStream, status: &str, body: &[u8]) -> std::io::Result<()> {
        let headers = format!(
            "HTTP/1.1 {status}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {len}\r\n\
             Access-Control-Allow-Origin: *\r\n\
             Access-Control-Allow-Methods: POST, OPTIONS\r\n\
             Access-Control-Allow-Headers: content-type\r\n\
             Access-Control-Allow-Private-Network: true\r\n\
             Access-Control-Max-Age: 600\r\n\
             Cache-Control: no-store\r\n\
             X-Content-Type-Options: nosniff\r\n\
             Connection: close\r\n\r\n",
            status = status, len = body.len());
        stream.write_all(headers.as_bytes())?;
        stream.write_all(body)?;
        stream.flush()
    }

    fn send(stream: &mut TcpStream, status: &str, kind: &str, body: &[u8], head_only: bool)
        -> std::io::Result<()> {
        let headers = format!(
            "HTTP/1.1 {status}\r\n\
             Content-Type: {kind}\r\n\
             Content-Length: {len}\r\n\
             Cache-Control: no-store\r\n\
             X-Content-Type-Options: nosniff\r\n\
             Connection: close\r\n\r\n",
            status = status, kind = kind, len = body.len());
        stream.write_all(headers.as_bytes())?;
        if !head_only {
            stream.write_all(body)?;
        }
        stream.flush()
    }

    /// The wire, not the drawing.
    ///
    /// veil.rs proves the rasteriser; these prove the path a real window takes
    /// to reach it — the query the old code threw away, the token check, the
    /// cross-origin refusal, and the one thing that would make the whole change
    /// pointless if it were ever wrong: that what goes out over the socket does
    /// not contain the credential.
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::veil;

        const VALUE: &str = "sk-veil-test-0123456789abcdef";

        /// What a real reveal puts behind a token: the drawn value, not the value.
        fn drawn() -> Vec<u8> {
            veil::draw(VALUE, &veil::Ask { px: 12.0, scale: 2.0, ink: [0xf2, 0xf3, 0xf5] })
                .expect("drawn")
        }

        fn ask(port: u16, request: &str) -> Vec<u8> {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
            stream.write_all(request.as_bytes()).expect("write");
            stream.flush().expect("flush");
            let mut out = Vec::new();
            let _ = stream.read_to_end(&mut out);
            out
        }

        fn get(port: u16, target: &str, extra: &str) -> Vec<u8> {
            ask(port, &format!(
                "GET {target} HTTP/1.1\r\nHost: localhost\r\n{extra}Connection: close\r\n\r\n"))
        }

        fn status(response: &[u8]) -> String {
            String::from_utf8_lossy(response).lines().next().unwrap_or("").to_string()
        }

        fn body(response: &[u8]) -> Vec<u8> {
            response.windows(4).position(|w| w == b"\r\n\r\n")
                .map(|at| response[at + 4..].to_vec()).unwrap_or_default()
        }

        #[test]
        fn the_veil_serves_a_picture_and_never_the_value() {
            if !veil::can_draw() {
                eprintln!("no system monospace font; skipping");
                return;
            }
            let port = serve().expect("a port");
            let token = veil::hold(drawn());

            // The page's own request, as the <img> makes it.
            let target = format!("/veil?t={token}&px=12&s=2&ink=f2f3f5");
            let response = get(port, &target, "Sec-Fetch-Site: same-origin\r\n");
            assert!(status(&response).contains("200 OK"), "{}", status(&response));
            assert!(String::from_utf8_lossy(&response).contains("Content-Type: image/png"));

            let png = body(&response);
            assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n", "that is not a PNG");
            // The whole point of the change, checked on the bytes that actually
            // cross the socket rather than on the ones the drawing returned.
            assert!(!response.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()),
                    "the credential went out over the wire");
            assert!(!response.windows(7).any(|w| w == b"sk-veil"));

            // A token that has been forgotten stops answering.
            assert!(veil::forget(&token));
            let after = get(port, &target, "");
            assert!(status(&after).contains("404"), "{}", status(&after));
        }

        #[test]
        fn a_made_up_token_gets_nothing() {
            let port = serve().expect("a port");
            let response = get(port, "/veil?t=deadbeef&px=12&s=1&ink=000000", "");
            assert!(status(&response).contains("404"), "{}", status(&response));
        }

        #[test]
        fn a_page_from_somewhere_else_is_refused() {
            if !veil::can_draw() {
                return;
            }
            let port = serve().expect("a port");
            let token = veil::hold(drawn());
            let target = format!("/veil?t={token}&px=12&s=1&ink=000000");
            // Not load-bearing — a page that cannot guess the token has nothing
            // to ask for — but the refusal should be there and should be the
            // refusal, not a picture.
            let response = get(port, &target, "Sec-Fetch-Site: cross-site\r\n");
            assert!(status(&response).contains("403"), "{}", status(&response));
            assert!(!response.windows(7).any(|w| w == b"sk-veil"));
            veil::forget(&token);
        }

        #[test]
        fn the_veil_answers_no_one_cross_origin_and_is_never_cached() {
            if !veil::can_draw() {
                return;
            }
            let port = serve().expect("a port");
            let token = veil::hold(drawn());
            let response = get(port, &format!("/veil?t={token}"), "");
            let head = String::from_utf8_lossy(&response).to_lowercase();
            // `/ask` is deliberately open to any origin. This must not be: a
            // page that got hold of a token should still not be able to read
            // the pixels back out of a fetch.
            assert!(!head.contains("access-control-allow-origin"),
                    "the veil answered cross-origin");
            assert!(head.contains("cache-control: no-store"),
                    "a picture of a credential must not be cached");
            veil::forget(&token);
        }

        #[test]
        fn the_page_and_the_mark_still_come_back() {
            let port = serve().expect("a port");
            assert!(status(&get(port, "/", "")).contains("200 OK"));
            assert!(status(&get(port, "/mark.png", "")).contains("200 OK"));
            assert!(status(&get(port, "/nothing", "")).contains("404"));
        }

        /// The bug this is here to stop coming back: the old handler read the
        /// path with `.split('?').next()`, so every query was discarded. A
        /// static route that stopped working the moment anything appended one
        /// would be a strange way to find that out.
        #[test]
        fn a_query_on_a_static_path_still_finds_it() {
            let port = serve().expect("a port");
            assert!(status(&get(port, "/?steady=1", "")).contains("200 OK"));
        }
    }
}


// ── "Add to PassBook" ───────────────────────────────────────────────────────
//
// A link names the keys a service wants. Everything that decides whether they
// are stored happens in the window and in the vault, not here: this only holds
// the most recent request until somebody looks at it.

/// One at a time. A second link replaces the first rather than queueing,
/// because a stack of credential prompts is how people start clicking through
/// them without reading.
static PENDING: OnceLock<std::sync::Mutex<Option<ask::Ask>>> = OnceLock::new();

fn pending() -> &'static std::sync::Mutex<Option<ask::Ask>> {
    PENDING.get_or_init(|| std::sync::Mutex::new(None))
}

/// Remember a request and wake the window.
fn remember_ask(app: &tauri::AppHandle, url: &str) {
    // Distinct per request, so approving cannot be replayed against whatever
    // arrived afterwards.
    let id = format!("{:x}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
    match ask::parse(url, &id) {
        Ok(parsed) => {
            if let Ok(mut slot) = pending().lock() {
                *slot = Some(parsed);
            }
            // The window may not exist yet on a cold start; it asks for the
            // pending request itself once it loads, so a missed event is not a
            // missed request.
            let _ = app.emit("passbook://ask", ());
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
        }
        Err(reason) => {
            let _ = app.emit("passbook://ask-refused", reason);
        }
    }
}

/// Take what a page posted, and put it in front of the person.
fn remember_page_ask(app: &tauri::AppHandle, body: &str, origin: &str) -> Result<(), String> {
    let id = format!("{:x}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
    let parsed = ask::parse_page(body, origin, &id)?;
    if let Ok(mut slot) = pending().lock() {
        *slot = Some(parsed);
    }
    let _ = app.emit("passbook://ask", ());
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
    Ok(())
}

/// What the window should be showing, if anything.
#[tauri::command]
fn pending_ask() -> Option<ask::Ask> {
    pending().lock().ok().and_then(|slot| slot.clone())
}

/// Put the request down without storing anything.
#[tauri::command]
fn dismiss_ask() {
    if let Ok(mut slot) = pending().lock() {
        *slot = None;
    }
}

/// Store a set of keys in one go, and clear the request that asked for them.
///
/// One CLI call rather than one per key: `passbook add --stdin` reads
/// `KEY=value` lines, so the whole set lands as a single operation with a
/// single line in the ledger, and a half-applied request cannot happen.
/// Values go down stdin and never appear in an argument list.
#[tauri::command]
fn apply_ask(id: String, typed: Vec<(String, String)>, replace: bool) -> Result<Value, String> {
    use std::io::Write;
    use std::process::Stdio;

    // Values the page handed over never went to the window, so they are read
    // back from here. `typed` fills only the keys nobody supplied.
    let wanted = {
        let slot = pending().lock().map_err(|_| "PassBook lost track of that request.")?;
        match slot.as_ref() {
            Some(current) if current.id == id => current.keys.clone(),
            _ => return Err("That request is no longer the one on screen.".into()),
        }
    };

    let mut lines = String::new();
    for key in &wanted {
        let value = match key.value.as_deref() {
            Some(held) => held.to_string(),
            None => typed
                .iter()
                .find(|(name, _)| name == &key.name)
                .map(|(_, value)| value.trim().to_string())
                .unwrap_or_default(),
        };
        if value.is_empty() {
            return Err(format!("{} has no value.", key.name));
        }
        // Belt and braces: `ask` refuses both already, and either one here
        // would write a key nobody approved.
        if key.name.contains(['\n', '\r', '=']) || value.contains(['\n', '\r']) {
            return Err(format!("{} cannot be stored as written.", key.name));
        }
        lines.push_str(&format!("{}={}\n", key.name, value));
    }
    if lines.is_empty() {
        return Err("Nothing to add.".into());
    }

    let mut args = vec!["add", "--stdin"];
    if replace {
        args.push("--replace");
    }
    let mut child = passbook_command()
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("Could not run PassBook: {error}"))?;
    {
        let stdin = child.stdin.as_mut().ok_or("Could not write to PassBook")?;
        stdin
            .write_all(lines.as_bytes())
            .map_err(|error| format!("Could not write to PassBook: {error}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("PassBook did not finish: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail = detail.trim();
        return Err(if detail.is_empty() { "Those keys were not added.".into() } else { detail.to_string() });
    }
    dismiss_ask();
    state()
}


// ── importing a .env ────────────────────────────────────────────────────────
//
// Dropping a `.env` on the window is the fastest way from "I have a project
// full of keys" to "they are in the vault". Both of these are thin: the CLI
// decides what a `.env` contains, what clashes, and what a kept-alongside copy
// should be called, so the window and the terminal cannot disagree about it.
//
// Values never come back here. The list is names, and the import is done by
// the CLI reading the same file again.

/// What is in a file, without importing any of it.
#[tauri::command]
fn inspect_env(path: String) -> Result<Value, String> {
    let target = path.trim();
    if target.is_empty() {
        return Err("Which file?".into());
    }
    let raw = run(&["import", target, "--dry-run", "--json"])?;
    serde_json::from_str(&raw)
        .map_err(|error| format!("PassBook returned something unreadable: {error}"))
}

/// Import the chosen keys, renaming the ones being kept alongside.
///
/// `renames` arrives as pairs so the window can offer "add as new" per key
/// without inventing the new name itself.
#[tauri::command]
fn import_env(
    path: String,
    only: Vec<String>,
    renames: Vec<(String, String)>,
    overwrite: bool,
) -> Result<Value, String> {
    let target = path.trim().to_string();
    if target.is_empty() {
        return Err("Which file?".into());
    }
    if only.is_empty() {
        return Err("Nothing was selected to import.".into());
    }
    let mut args: Vec<String> = vec!["import".into(), target, "--only".into()];
    args.extend(only.iter().cloned());
    if !renames.is_empty() {
        args.push("--as".into());
        for (from, to) in &renames {
            args.push(format!("{from}={to}"));
        }
    }
    if overwrite {
        args.push("--overwrite".into());
    }
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let detail = run(&borrowed)?;
    let next = state()?;
    Ok(serde_json::json!({ "ok": true, "detail": detail.trim(), "state": next }))
}

fn main() {
    // Before anything else, and before Tauri: this binary is also the child a
    // broker spawns to draw one credential. That run has no window, no store
    // access and no argument beyond what it was told to draw.
    if drew() {
        return;
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            // A link can arrive before the window exists (cold start) or long
            // after it (the app was already open), so both are wired: the
            // launch URL is read once, and the handler stays for the rest.
            {
                // A page that posts to the loopback server ends up in the same
                // place a link does: one pending request, one person deciding.
                let handle = app.handle().clone();
                let _ = ui::ON_ASK.set(Box::new(move |body: &str, origin: &str| {
                    remember_page_ask(&handle, body, origin)
                }));
            }
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                let handle = app.handle().clone();
                app.deep_link().on_open_url(move |event| {
                    for url in event.urls() {
                        remember_ask(&handle, url.as_str());
                    }
                });
                if let Ok(Some(urls)) = app.deep_link().get_current() {
                    for url in urls {
                        remember_ask(app.handle(), url.as_str());
                    }
                }
            }
            // Asked of Tauri rather than derived from the executable's path:
            // the answer differs per platform and per bundle format, and
            // guessing it wrong means falling back to "not installed".
            if let Ok(directory) = app.path().resource_dir() {
                let _ = RESOURCES.set(directory);
            }
            // Tell the coding agents on this machine that PassBook is here.
            //
            // The command line does this during `passbook install`, and most
            // people never run it: they download the app, or they get the CLI
            // through `uv tool install`, which installs a package and runs
            // nothing. Either way the agents were never told, and an agent that
            // has not been told reports a sealed key as missing.
            //
            // Idempotent and quiet. It rewrites a delimited block only when the
            // text differs, so the ordinary case is a few file reads, and it
            // runs off the main thread because none of it is worth delaying a
            // window for.
            std::thread::spawn(|| {
                let _ = passbook_command()
                    .arg("brief")
                    .arg("install")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            });
            let port = ui::serve()?;
            // `localhost`, not `127.0.0.1`: the name is what a passkey binds to,
            // and an address is refused as "an invalid domain".
            let steady = (ui::PREFERRED_PORT..ui::PREFERRED_PORT + ui::NEIGHBOURS).contains(&port);
            let url = format!("http://localhost:{port}/?steady={}", u8::from(steady));
            let window = tauri::WebviewWindowBuilder::new(
                app,
                "main",
                tauri::WebviewUrl::External(url.parse()?),
            )
            .title("PassBook")
            .inner_size(1040.0, 760.0)
            .min_inner_size(860.0, 600.0)
            .resizable(true)
            // The veil's other half. Drawing the value instead of writing it
            // takes it out of the accessibility tree; this takes it out of
            // screenshots, screen recordings and screen shares — the same
            // `NSWindowSharingType::None` and `WDA_EXCLUDEFROMCAPTURE` a video
            // player uses, reached through tao.
            //
            // Neither is worth much alone. A drawn value with no capture
            // protection is a value an agent screenshots and reads with OCR; a
            // protected window full of DOM text is a value it reads out of the
            // accessibility tree without taking a screenshot at all. Together
            // there is neither text nor pixels to take.
            //
            // Always on rather than only while a value is showing: toggling it
            // races a screenshot on a timer, and the cost of leaving it on —
            // this window does not appear in a screen recording, so a support
            // screenshot of it comes out empty — is the correct trade for a
            // credential manager and is written down in the README.
            //
            // Linux gets nothing here. tao documents the call as unsupported
            // there and compiles it out, so on Linux the drawn value is the
            // whole of the protection. `capture_protection` in `state` is what
            // tells the window which of those it is on, rather than letting it
            // claim a guarantee this platform did not give.
            .content_protected(true);
            // The overlay title bar is what lets the sidebar run to the top of
            // the window, and it exists only on macOS.
            #[cfg(target_os = "macos")]
            let window = window
                .title_bar_style(tauri::TitleBarStyle::Overlay)
                .hidden_title(true);
            window.build()?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            state, set_mode, unlock, lock, resolve, broker, revoke, add_key, remove_key, reveal_key,
            forget_reveal, copy_key, capture_protection,
            key_history, vault_state, vault_signin, vault_signout, vault_create_profile,
            vault_use_profile, vault_seal, vault_unseal, vault_secure, set_key_group, set_key_audience, set_key_scope, set_keys_scope, remove_keys,
            access_matrix, oauth_state, oauth_refresh, oauth_disconnect, oauth_connect,
            set_workspace, export_store, inspect_export, import_store, make_recovery_code,
            forget_machine, verify_record, vault_create_workspace, vault_add_passkey,
            vault_signin_passkey, biometric_status, vault_signin_device, vault_trust_device,
            set_key_projects, set_confirmation,
            pending_ask, dismiss_ask, apply_ask, inspect_env, import_env
        ])
        .run(tauri::generate_context!())
        .expect("PassBook failed to start");
}
