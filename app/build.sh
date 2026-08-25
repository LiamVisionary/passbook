#!/bin/sh
# Build, sign and notarize PassBook for distribution.
#
#   ./build.sh
#
# Credentials come from the machine's PassBook store via `passbook-run`, so
# nothing is written into this repo and nothing lands in a command line.
#
# The one subtlety, which cost a build to find:
#
#   APPLE_CERTIFICATE and APPLE_CERTIFICATE_PASSWORD are for CI, where there is
#   no login keychain and Tauri must import the certificate itself. On a
#   developer Mac the identity is ALREADY in the login keychain, and if Tauri
#   sees those two variables it builds a second, temporary keychain and imports
#   the same certificate into it. `codesign` then finds the identity twice and
#   refuses:
#
#       ...: ambiguous (matches "Developer ID Application: Rizzma, Inc. ..."
#       in login.keychain-db and "..." in <temp>.keychain-db)
#
#   So they are unset here. Do NOT "fix" that by removing the `env -u`.
#
# That failure is also the clearest argument in this repo for scoped credential
# requests over handing a process the whole environment: the build broke on two
# variables it never needed, because a tool changed behaviour merely by seeing
# them.

set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

[ -d node_modules ] || npm install --silent

passbook-run -- env -u APPLE_CERTIFICATE -u APPLE_CERTIFICATE_PASSWORD \
  npx tauri build "$@" || true

# Tauri's own DMG step drives Finder over AppleScript to arrange the window,
# which needs a TCC grant no background or CI process can obtain — so it fails
# with no message after the app has already been signed, notarised and stapled.
# Build the image with hdiutil instead: same result, no Finder, no permission.
APP="src-tauri/target/release/bundle/macos/PassBook.app"
DMG="src-tauri/target/release/bundle/dmg/PassBook_1.0.0_aarch64.dmg"
[ -d "$APP" ] || { echo "no app bundle to package" >&2; exit 1; }

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
mkdir -p "$(dirname "$DMG")"
rm -f "$DMG"
hdiutil create -volname PassBook -srcfolder "$STAGE" -ov -format UDZO "$DMG"

# The image needs its own signature and its own notarisation ticket; the app's
# does not travel with it.
passbook-run -- sh -c 'codesign --force --timestamp --sign "$APPLE_SIGNING_IDENTITY" "'"$DMG"'"'
xcrun notarytool submit "$DMG" --keychain-profile rizzma-notary --wait
xcrun stapler staple "$DMG"

echo
echo "Verifying what will actually reach a user:"
spctl --assess --type open --context context:primary-signature --verbose=2 "$DMG"
