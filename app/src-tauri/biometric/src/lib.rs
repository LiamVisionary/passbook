// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rizzma, Inc.
//! Device-owner verification, behind a small safe API.
//!
//! Why this exists rather than a passkey. A passkey needs a browser: measured
//! from inside this app's own webview, WebAuthn's
//! `isUserVerifyingPlatformAuthenticatorAvailable()` answers false, and it
//! keeps answering false when the window is served over `http://localhost` and
//! when the bundle carries a Developer ID signature with a real team
//! identifier. A WKWebView is not a browser and does not get a platform
//! authenticator.
//!
//! What a native app can do is ask LocalAuthentication, which is what Touch ID
//! is. HivemindOS's desktop app reaches the same conclusion and does the same
//! thing; its button says "passkey" and what runs is this.
//!
//! The Objective-C stays in this crate so the app crate can keep forbidding
//! unsafe code.

#[cfg(target_os = "macos")]
mod mac;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BiometryKind {
    TouchId,
    FaceId,
    OpticId,
    Unknown,
}

impl BiometryKind {
    /// The value the window matches on. Stable regardless of what the platform
    /// calls it, because the window has to name it in a sentence.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TouchId => "touch-id",
            Self::FaceId => "face-id",
            Self::OpticId => "optic-id",
            Self::Unknown => "biometric",
        }
    }

    /// What to call it on screen.
    pub fn label(self) -> &'static str {
        match self {
            Self::TouchId => "Touch ID",
            Self::FaceId => "Face ID",
            Self::OpticId => "Optic ID",
            Self::Unknown => "your device",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BiometricStatus {
    pub available: bool,
    pub kind: Option<BiometryKind>,
}

/// Whether this device can verify its owner, and by what. Asks nothing of the
/// person: no prompt, no sensor, no sound.
pub fn status() -> BiometricStatus {
    #[cfg(target_os = "macos")]
    {
        mac::status()
    }
    #[cfg(not(target_os = "macos"))]
    {
        BiometricStatus { available: false, kind: None }
    }
}

/// Ask the owner to prove they are present. Blocks until they answer.
pub fn authenticate(reason: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        mac::authenticate(reason)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = reason;
        Err("This platform has no device authentication PassBook can use.".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{status, BiometryKind};

    #[test]
    fn every_kind_has_a_stable_value_and_a_name_for_a_sentence() {
        for (kind, value, label) in [
            (BiometryKind::TouchId, "touch-id", "Touch ID"),
            (BiometryKind::FaceId, "face-id", "Face ID"),
            (BiometryKind::OpticId, "optic-id", "Optic ID"),
            (BiometryKind::Unknown, "biometric", "your device"),
        ] {
            assert_eq!(kind.as_str(), value);
            assert_eq!(kind.label(), label);
        }
    }

    #[test]
    fn a_device_that_can_verify_says_how() {
        // Available with no kind would leave the window with nothing to call
        // it, and a kind with nothing available would offer a button that
        // cannot work — the exact shape of bug this replaced.
        let status = status();
        assert_eq!(status.available, status.kind.is_some());
    }
}
