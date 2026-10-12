//! The app replacing itself with a newer release.
//!
//! Before 1.10.6 there was no way to do this from inside the app: a person
//! downloaded a new disk image and dragged it over the old one, and an app
//! installed in September was still the September app in October while the
//! command line beside it had moved on six releases. The window drives that
//! command line, so the two drifting apart is not cosmetic: a page can call a
//! command the installed CLI has, with a window that does not know the page.
//!
//! The mechanism is Tauri's updater and nothing of ours. A release publishes
//! `latest.json` beside its installers (scripts/update-manifest.py), naming one
//! update file per platform and that file's signature. The app fetches the
//! manifest from the newest published release, and installs a file only if its
//! signature verifies against the public key compiled into this binary
//! (tauri.conf.json, `plugins.updater.pubkey`). The private half signs in the
//! release workflow and is in no checkout. A draft release has no
//! `releases/latest/download/...` address, so nothing is offered until a person
//! publishes it.
//!
//! It never installs by itself. `check` asks; `install` is a button.

use serde_json::{json, Value};
use tauri::AppHandle;
use tauri_plugin_updater::UpdaterExt;

/// Where a person gets a release by hand, for the one install that cannot
/// replace itself.
pub const RELEASES: &str = "https://github.com/LiamVisionary/passbook/releases/latest";

/// Whether this copy can be swapped for a newer one where it sits.
///
/// Everything can except a Linux package: a `.deb` is owned by the package
/// manager and lives under `/usr`, and the updater's Linux file is an AppImage.
/// An AppImage says it is one through `APPIMAGE`, set by its own runtime.
fn replaces_itself() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("APPIMAGE").is_some()
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

/// This version, the newest published one, and whether the button will work.
///
/// A failure to ask is an answer, not an error: offline is the ordinary reason,
/// and the page should say "could not check" beside the version it does know.
pub fn check(app: &AppHandle) -> Value {
    let current = app.package_info().version.to_string();
    let found = tauri::async_runtime::block_on(async {
        let updater = app.updater().map_err(|error| error.to_string())?;
        updater.check().await.map_err(|error| error.to_string())
    });
    match found {
        Ok(Some(update)) => json!({
            "current": current, "latest": update.version, "available": true,
            "notes": update.body.unwrap_or_default(), "can_install": replaces_itself(),
        }),
        Ok(None) => json!({
            "current": current, "latest": current, "available": false, "can_install": replaces_itself(),
        }),
        Err(error) => json!({
            "current": current, "latest": Value::Null, "available": false,
            "can_install": replaces_itself(), "error": error,
        }),
    }
}

/// Download the newest release, verify its signature, and put it where this
/// copy is. Returns the version now on disk; the caller restarts into it.
pub fn install(app: &AppHandle) -> Result<String, String> {
    if !replaces_itself() {
        return Err("This copy was installed as a package. Install the new package from the releases page.".into());
    }
    tauri::async_runtime::block_on(async {
        let updater = app.updater().map_err(|error| error.to_string())?;
        let Some(update) = updater.check().await.map_err(|error| error.to_string())? else {
            return Err("This is already the newest release.".to_string());
        };
        let version = update.version.clone();
        update
            .download_and_install(|_, _| {}, || {})
            .await
            .map_err(|error| format!("The update could not be installed: {error}"))?;
        Ok(version)
    })
}
