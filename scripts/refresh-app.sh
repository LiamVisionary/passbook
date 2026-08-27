#!/usr/bin/env bash
# Put a freshly built binary into the .app and leave the bundle SIGNED.
#
# Two reasons this exists rather than a bare `cp`.
#
# Copying the binary in on its own breaks the bundle signature: the Info.plist
# stops being bound and the sealed resources go, so `codesign --verify` fails.
#
# And the signature is not cosmetic here. macOS gates the WebAuthn platform
# authenticator on it: in an ad-hoc signed bundle the window's
# `isUserVerifyingPlatformAuthenticatorAvailable()` answers false, so Touch ID
# is refused before any prompt is drawn. A Developer ID signature is what
# HivemindOS's app has and this one did not.
#
# The identity is resolved rather than pasted. The same certificate can sit in
# more than one keychain with a different hash in each, and naming it by hash
# from the wrong one fails as "no identity found", while naming it by its
# common name fails as "ambiguous". Only the login keychain is searched,
# because that is the one whose password is the one you know.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
app="$root/app/src-tauri/target/release/bundle/macos/PassBook.app"
built="$root/app/src-tauri/target/release/passbook-app"
login="$HOME/Library/Keychains/login.keychain-db"

[ -f "$built" ] || { echo "no built binary at $built" >&2; exit 1; }

identity="${PASSBOOK_SIGN_IDENTITY:-${APPLE_SIGNING_IDENTITY:-}}"
if [ -z "$identity" ] && [ -f "$login" ]; then
  identity="$(security find-identity -v -p codesigning "$login" 2>/dev/null \
    | awk '/Developer ID Application/ {print $2; exit}')"
fi
if [ -z "$identity" ]; then
  identity="-"
  echo "note: no Developer ID in the login keychain — signing ad-hoc." >&2
  echo "      Touch ID will stay unavailable in the window until it is signed." >&2
fi

# An interrupted signing leaves these behind and every later attempt then fails
# with "invalid or unsupported format for signature".
find "$app" -name "*.cstemp" -delete 2>/dev/null || true

cp "$built" "$app/Contents/MacOS/passbook-app"
if [ "$identity" = "-" ]; then
  codesign --force --deep --sign - "$app"
else
  codesign --force --deep --options runtime --keychain "$login" --sign "$identity" "$app"
fi
codesign --verify --deep --strict "$app" && echo "signature verifies"
codesign -dv --verbose=2 "$app" 2>&1 | grep -E "^Signature|TeamIdentifier|Authority=Developer ID Application" || true
