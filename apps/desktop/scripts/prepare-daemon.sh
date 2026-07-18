#!/bin/sh
set -eu

profile="${1:-debug}"
case "$profile" in
  debug | release) ;;
  *)
    echo "usage: prepare-daemon.sh [debug|release]" >&2
    exit 2
    ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
desktop_dir=$(dirname "$script_dir")
repository_root=$(CDPATH= cd -- "$desktop_dir/../.." && pwd)
target_triple=$(rustc --print host-tuple)
target_dir="$repository_root/target"

if [ "$profile" = "release" ]; then
  cargo build \
    --manifest-path "$repository_root/Cargo.toml" \
    --package birdcode-daemon \
    --target "$target_triple" \
    --target-dir "$target_dir" \
    --release
else
  cargo build \
    --manifest-path "$repository_root/Cargo.toml" \
    --package birdcode-daemon \
    --target "$target_triple" \
    --target-dir "$target_dir"
fi

extension=""
case "$target_triple" in
  *-windows-*) extension=".exe" ;;
esac

source_binary="$target_dir/$target_triple/$profile/birdcode-daemon$extension"
sidecar_dir="$desktop_dir/src-tauri/binaries"
sidecar_binary="$sidecar_dir/birdcode-daemon-$target_triple$extension"
mkdir -p "$sidecar_dir"
cp "$source_binary" "$sidecar_binary"
