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

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

/// Where the CLI lives. An installed `passbook` on PATH wins; otherwise fall
/// back to the checkout this binary was built from, so a development build
/// works without an install step.
fn passbook_command() -> Command {
    if let Ok(explicit) = std::env::var("PASSBOOK_CLI") {
        return Command::new(explicit);
    }
    let installed = PathBuf::from(std::env::var("HOME").unwrap_or_default())
        .join(".local/bin/passbook");
    if installed.exists() {
        return Command::new(installed);
    }
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

/// Show one value.
///
/// The only command here that returns a secret, and it is deliberately narrow:
/// one key, by name, recorded as a `reveal`. A credential manager that cannot
/// show you your own credential is not one — you keep keys in order to paste
/// them somewhere eventually — but every other call in this file stays free of
/// values so that "can this leak?" is answerable by reading the signature.
#[tauri::command]
fn reveal_key(name: String) -> Result<String, String> {
    if name.trim().is_empty() {
        return Err("Which key?".into());
    }
    Ok(run(&["reveal", name.trim()])?.trim_end_matches('\n').to_string())
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

/// Say who a key is for: everyone, only these agents, or everyone except these.
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
            return Err("Name at least one agent.".into());
        }
        for agent in &agents {
            args.push(agent.trim());
        }
    }
    run(&args)?;
    state()
}

/// Which agents can read which keys. Fetched on demand: a full grid over a
/// large store is not something to ship with every background refresh.
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

#[tauri::command]
fn vault_signin(profile: String, password: String) -> Result<Value, String> {
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
    run_with_password(&args, &password)?;
    vault_state()
}

#[tauri::command]
fn vault_signout() -> Result<Value, String> {
    run(&["signout"])?;
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
/// Fetched on demand rather than shipped with every state refresh: a store of
/// several hundred keys would otherwise carry a history nobody asked to see.
#[tauri::command]
fn key_history(name: String) -> Result<Value, String> {
    if name.trim().is_empty() {
        return Err("Which key?".into());
    }
    run_json(&["history", name.trim(), "--json", "--limit", "60"])
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            state, set_mode, unlock, lock, resolve, broker, revoke, add_key, remove_key, reveal_key,
            key_history, vault_state, vault_signin, vault_signout, vault_create_profile,
            vault_use_profile, vault_seal, vault_unseal, vault_secure, set_key_group, set_key_audience, set_key_scope, set_keys_scope, remove_keys,
            access_matrix, oauth_state, oauth_refresh, oauth_disconnect, oauth_connect,
            set_workspace, export_store, inspect_export, import_store, make_recovery_code,
            set_key_projects, set_confirmation
        ])
        .run(tauri::generate_context!())
        .expect("PassBook failed to start");
}
