#!/usr/bin/env bash
# Build, Developer-ID-sign, notarize, and package the AgentVault release that unlocks
# the Secure Enclave key tier. Run it yourself on a Mac with your Developer ID cert in
# the login keychain — it makes no network calls except the notary submission and runs
# no servers.
#
# WHY a bundle: creating a Secure Enclave key (SecKeyCreateRandomKey +
# kSecAttrTokenIDSecureEnclave, see internal/enclave/enclave_darwin.m) requires the
# com.apple.application-identifier entitlement AUTHORIZED BY A PROVISIONING PROFILE, and
# a bare Mach-O has nowhere to hold a profile. So `avd` (the only binary that touches the
# Enclave) is wrapped in an app-like bundle with Contents/embedded.provisionprofile.
# `av` never calls SecKey, so it ships as a bare, signed+notarized binary.
#
# Prereqs (see docs/signing-and-notarization.md):
#   - Developer ID Application cert installed   (security find-identity -p codesigning -v)
#   - notarytool keychain profile               (xcrun notarytool store-credentials …)
#   - a Developer ID provisioning profile for the App ID, saved to $PROFILE_PATH
#
# Usage:  TEAM_ID=ABCDE12345 DEV_ID="Developer ID Application: Jane Doe (ABCDE12345)" \
#         NOTARY_PROFILE=AgentVault ./scripts/release-signed.sh [VERSION]
set -euo pipefail

# ---- config (override via env) ---------------------------------------------------------
TEAM_ID="${TEAM_ID:-__TEAM_ID__}"                              # 10-char Apple Team ID
DEV_ID="${DEV_ID:-Developer ID Application: __NAME__ (${TEAM_ID})}"
NOTARY_PROFILE="${NOTARY_PROFILE:-AgentVault}"                 # notarytool store-credentials name
PROFILE_PATH="${PROFILE_PATH:-packaging/agentvault.provisionprofile}"
VERSION="${1:-$(git describe --tags --always 2>/dev/null || echo dev)}"
VER="${VERSION#v}"                                            # CFBundle* / Cask want no leading 'v'

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
APP="$DIST/AgentVault.app"
TARBALL="$DIST/agentvault-${VERSION}-macos.tar.gz"

# ---- preflight -------------------------------------------------------------------------
[ "$TEAM_ID" = "__TEAM_ID__" ] && { echo "set TEAM_ID / DEV_ID / NOTARY_PROFILE — see docs/signing-and-notarization.md" >&2; exit 2; }
[ -f "$PROFILE_PATH" ] || { echo "missing provisioning profile at $PROFILE_PATH" >&2; exit 2; }
security find-identity -p codesigning -v | grep -q "$TEAM_ID" || { echo "no codesigning identity for team $TEAM_ID in keychain" >&2; exit 2; }

rm -rf "$DIST"; mkdir -p "$APP/Contents/MacOS"

# ---- build (CGO for the Touch ID / Enclave / Keychain cgo paths) -----------------------
echo "==> building $VERSION"
CGO_ENABLED=1 go build -ldflags "-X main.version=$VERSION" -o "$DIST/av"               "$ROOT/cmd/av"
CGO_ENABLED=1 go build -ldflags "-X main.version=$VERSION" -o "$APP/Contents/MacOS/avd" "$ROOT/cmd/avd"

# ---- assemble the avd bundle -----------------------------------------------------------
sed "s/__VERSION__/$VER/g"   "$ROOT/packaging/avd.app.Info.plist.template" > "$APP/Contents/Info.plist"
cp "$PROFILE_PATH" "$APP/Contents/embedded.provisionprofile"
ENTITLEMENTS="$DIST/avd.entitlements"
sed "s/__TEAM_ID__/$TEAM_ID/g" "$ROOT/packaging/avd.entitlements.template" > "$ENTITLEMENTS"

# ---- sign (hardened runtime + secure timestamp; entitlements only on avd) --------------
echo "==> signing"
codesign --force --options runtime --timestamp \
  --entitlements "$ENTITLEMENTS" --sign "$DEV_ID" "$APP"
codesign --force --options runtime --timestamp --sign "$DEV_ID" "$DIST/av"

echo "==> avd entitlements (must list application-identifier + team-identifier):"
codesign -d --entitlements - "$APP" 2>/dev/null | grep -E "application-identifier|team-identifier" || true
codesign --verify --strict --deep --verbose=2 "$APP"
codesign --verify --strict --verbose=2 "$DIST/av"

# ---- notarize (av bare + the app), then staple the app ---------------------------------
echo "==> notarizing (uploads to Apple and waits)"
ditto -c -k --keepParent "$APP" "$DIST/AgentVault.app.zip"
ditto -c -k "$DIST/av" "$DIST/av.zip"
xcrun notarytool submit "$DIST/AgentVault.app.zip" --keychain-profile "$NOTARY_PROFILE" --wait
xcrun notarytool submit "$DIST/av.zip"             --keychain-profile "$NOTARY_PROFILE" --wait
# Bundles can be stapled (offline Gatekeeper); a bare Mach-O (av) cannot — it is
# verified online by Gatekeeper on first run.
xcrun stapler staple "$APP"

# ---- package for the Homebrew Cask -----------------------------------------------------
echo "==> packaging $TARBALL"
( cd "$DIST" && tar -czf "$TARBALL" av AgentVault.app )
SHA="$(shasum -a 256 "$TARBALL" | awk '{print $1}')"

# ---- emit the ArtifactManifest for `zamokctl cask` -------------------------------------
# zamokctl cask reads this manifest (+ packaging/agentvault-cask.json) to render and push
# Casks/agentvault.rb to the tap. minMacOS is read from the bundle we just signed, so it
# stays the single source of truth (LSMinimumSystemVersion in avd.app.Info.plist.template).
MANIFEST="$DIST/manifest.json"
MIN_MACOS="$(/usr/libexec/PlistBuddy -c 'Print :LSMinimumSystemVersion' "$APP/Contents/Info.plist")"
URL="https://github.com/beshkenadze/agentvault/releases/download/${VERSION}/$(basename "$TARBALL")"
jq -n \
  --arg artifact      "$(basename "$TARBALL")" \
  --arg sha256        "$SHA" \
  --arg shortVersion  "$VER" \
  --arg bundleVersion "$VER" \
  --arg bundleId      "com.beshkenadze.agentvault" \
  --arg appBundleName "AgentVault.app" \
  --arg minMacOS      "$MIN_MACOS" \
  '{
    artifact:      $artifact,
    sha256:        $sha256,
    shortVersion:  $shortVersion,
    bundleVersion: $bundleVersion,
    bundleId:      $bundleId,
    appBundleName: $appBundleName,
    minMacOS:      $minMacOS,
    format:        "tarball",
    notarized:     true,
    stapled:       true
  }' > "$MANIFEST"

cat <<EOF

done.
  tarball  : $TARBALL
  sha256   : $SHA
  url      : $URL
  manifest : $MANIFEST

Next — publish the Homebrew cask via zamokctl (tap-host github, store=url passthrough):
  # 1. publish the tarball to the GitHub release (if not already):
  gh release create ${VERSION} "$TARBALL" --repo beshkenadze/agentvault   # or: gh release upload ${VERSION} "$TARBALL"
  # 2. render + push Casks/agentvault.rb to the tap (needs GITHUB_TOKEN):
  zamokctl cask \\
    --manifest "$MANIFEST" \\
    --metadata packaging/agentvault-cask.json \\
    --store url --url "$URL" \\
    --tap-host github --tap beshkenadze/homebrew-tap
  # 3. Test:  brew install --cask beshkenadze/tap/agentvault
  #           av version   # key should show: enclave

  (manual fallback: hand-edit the tap's Casks/agentvault.rb — version "$VER" / sha256 "$SHA".)
EOF
