#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
desktop_dir=$(dirname "$script_dir")
repository_root=$(CDPATH= cd -- "$desktop_dir/../.." && pwd)

export CARGO_TARGET_DIR="$repository_root/target"
export CARGO_BUILD_TARGET="$(rustc --print host-tuple)"

sh "$script_dir/prepare-daemon.sh" debug
cd "$desktop_dir"
tauri dev --config src-tauri/tauri.sidecar.conf.json
