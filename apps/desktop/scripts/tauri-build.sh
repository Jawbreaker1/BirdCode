#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
desktop_dir=$(dirname "$script_dir")
repository_root=$(CDPATH= cd -- "$desktop_dir/../.." && pwd)

export CARGO_TARGET_DIR="$repository_root/target"
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
  app_bundle="$repository_root/target/$CARGO_BUILD_TARGET/release/bundle/macos/BirdCode.app"
  dmg_dir="$repository_root/target/$CARGO_BUILD_TARGET/release/bundle/dmg"

  if [ -d "$app_bundle" ]; then
    xattr -cr "$app_bundle"
    codesign --verify --deep --strict "$app_bundle"
  fi

  for dmg_bundle in "$dmg_dir"/*.dmg; do
    [ -f "$dmg_bundle" ] || continue
    hdiutil verify "$dmg_bundle"
  done
fi
