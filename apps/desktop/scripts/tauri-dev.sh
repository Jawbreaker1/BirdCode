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

sh "$script_dir/prepare-daemon.sh" debug
cd "$desktop_dir"
tauri dev --config src-tauri/tauri.sidecar.conf.json
