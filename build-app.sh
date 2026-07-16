#!/usr/bin/env bash
# Build authkit.app UNSIGNED for local dev: build-app.sh <TEAM_ID> [profile-path]
# Sign-free by design; signing/notarization is release.yml's job.

set -euo pipefail

TEAM_ID="${1:?usage: build-app.sh <TEAM_ID> [provisioning-profile-path]}"
PROFILE_PATH="${2:-}"

# Keychain.swift's access-group literal is bound to SXKCTF23Q2; a different-team
# cert would errSecMissingEntitlement at runtime, so fail loud before compiling.
EXPECTED_TEAM_ID="SXKCTF23Q2"
if [ "$TEAM_ID" != "$EXPECTED_TEAM_ID" ]; then
	echo "build-app.sh: TEAM_ID '$TEAM_ID' != '$EXPECTED_TEAM_ID' — Keychain.swift's keychain-access-group literal is bound to $EXPECTED_TEAM_ID" >&2
	exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFO_PLIST="$HERE/Info.plist"
ENTITLEMENTS_TEMPLATE="$HERE/authkit.entitlements"

BUILD_DIR="$HERE/build"
APP="$BUILD_DIR/authkit.app"
MACOS_DIR="$APP/Contents/MacOS"

rm -rf "$APP"
mkdir -p "$MACOS_DIR"

# AUTHKIT_UNIVERSAL=1 builds arm64 + x86_64 (CI sets it).
if [ "${AUTHKIT_UNIVERSAL:-0}" = "1" ]; then
	swift build -c release --package-path "$HERE" --arch arm64 --arch x86_64 >&2
	BINARY="$HERE/.build/apple/Products/Release/authkit"
else
	swift build -c release --package-path "$HERE" >&2
	BINARY="$HERE/.build/release/authkit"
fi
cp "$BINARY" "$MACOS_DIR/authkit"

cp "$INFO_PLIST" "$APP/Contents/Info.plist"

# Materialize the entitlements with TEAM_ID substituted, next to the bundle, so
# the CI signing step can pass them straight to codesign.
sed "s/\$(TEAM_ID)/$TEAM_ID/g" "$ENTITLEMENTS_TEMPLATE" \
	> "$BUILD_DIR/authkit.entitlements"

if [ -n "$PROFILE_PATH" ]; then
	cp "$PROFILE_PATH" "$APP/Contents/embedded.provisionprofile"
fi

echo "$APP"
