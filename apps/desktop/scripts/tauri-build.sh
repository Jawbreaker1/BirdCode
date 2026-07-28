#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
desktop_dir=$(dirname "$script_dir")
repository_root=$(CDPATH= cd -- "$desktop_dir/../.." && pwd)

if [ "${BIRDCODE_BUILD_CACHE_WRAPPED:-}" != "1" ]; then
  exec node "$repository_root/scripts/birdcode_cached_command.mjs" -- sh "$0" "$@"
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:?BirdCode cache runner did not set CARGO_TARGET_DIR}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CARGO_BUILD_TARGET="$(rustc --print host-tuple)"

sh "$script_dir/prepare-daemon.sh" release
cd "$desktop_dir"
tauri build --target "$CARGO_BUILD_TARGET" --config src-tauri/tauri.sidecar.conf.json

# Finder/FileProvider metadata can be attached to a generated bundle when the
# checkout lives in a managed macOS folder. That metadata is not application
# content and `codesign --strict` rejects it even though Tauri signed the same
# bytes successfully. Remove it only from the generated bundle, then verify the
# standalone app and disk image rather than treating file creation as success.
if [ "$(uname -s)" = "Darwin" ]; then
  app_bundle="$CARGO_TARGET_DIR/$CARGO_BUILD_TARGET/release/bundle/macos/BirdCode.app"
  dmg_dir="$CARGO_TARGET_DIR/$CARGO_BUILD_TARGET/release/bundle/dmg"

  if [ -d "$app_bundle" ]; then
    xattr -cr "$app_bundle"
    codesign --verify --deep --strict "$app_bundle"
  fi

  for dmg_bundle in "$dmg_dir"/*.dmg; do
    [ -f "$dmg_bundle" ] || continue
    hdiutil verify "$dmg_bundle"
  done
fi
