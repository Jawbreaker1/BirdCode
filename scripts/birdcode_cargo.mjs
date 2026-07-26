import { spawnSync } from "node:child_process";
import { prepareCache } from "./build_cache.mjs";

async function main() {
  const prepared = await prepareCache();
  const cargo = process.env.BIRDCODE_CARGO_BIN ?? "cargo";
  const result = spawnSync(cargo, process.argv.slice(2), {
    cwd: process.cwd(),
    env: {
      ...process.env,
      CARGO_INCREMENTAL: process.env.CARGO_INCREMENTAL ?? "0",
      CARGO_TARGET_DIR: prepared.cache_path,
    },
    stdio: "inherit",
  });
  if (result.error) {
    throw result.error;
  }
  if (result.signal) {
    process.stderr.write(`Cargo terminated by ${result.signal}\n`);
    process.exitCode = 1;
    return;
  }
  process.exitCode = result.status ?? 1;
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
