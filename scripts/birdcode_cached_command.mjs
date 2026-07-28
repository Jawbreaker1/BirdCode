import { spawn } from "node:child_process";
import { pathToFileURL } from "node:url";
import {
  acquireBuildCacheLease,
  prepareCache,
  releaseBuildCacheLease,
  resolveCachePath,
  validateBuildCacheLease,
} from "./build_cache.mjs";

export const BUILD_CACHE_LEASE_ENV = "BIRDCODE_BUILD_CACHE_LEASE_ID";
export const BUILD_CACHE_WRAPPED_ENV = "BIRDCODE_BUILD_CACHE_WRAPPED";

function runForeground(command, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: "inherit",
    });
    const forwardedSignals = ["SIGINT", "SIGTERM", "SIGHUP"];
    const handlers = new Map();
    let settled = false;

    const finish = (callback) => {
      if (settled) {
        return;
      }
      settled = true;
      for (const [signal, handler] of handlers) {
        process.off(signal, handler);
      }
      callback();
    };

    for (const signal of forwardedSignals) {
      const handler = () => {
        if (child.exitCode === null && child.signalCode === null) {
          child.kill(signal);
        }
      };
      handlers.set(signal, handler);
      process.on(signal, handler);
    }

    child.once("error", (error) => finish(() => reject(error)));
    child.once("close", (status, signal) => {
      finish(() => resolve({ status: status ?? 1, signal }));
    });
  });
}

export async function runCachedCommand({
  command,
  args = [],
  cwd = process.cwd(),
  environment = process.env,
} = {}) {
  if (typeof command !== "string" || command.length === 0) {
    throw new Error("A non-empty cached command is required");
  }
  const cachePath = resolveCachePath(environment);
  const inheritedLeaseId = environment[BUILD_CACHE_LEASE_ENV];
  let lease;
  let ownsLease = false;

  if (inheritedLeaseId) {
    lease = await validateBuildCacheLease({
      cachePath,
      leaseId: inheritedLeaseId,
    });
  } else {
    lease = await acquireBuildCacheLease({ cachePath });
    ownsLease = true;
  }

  try {
    const prepared = await prepareCache({ cachePath });
    return await runForeground(command, args, {
      cwd,
      env: {
        ...environment,
        [BUILD_CACHE_LEASE_ENV]: lease.lease_id,
        [BUILD_CACHE_WRAPPED_ENV]: "1",
        CARGO_INCREMENTAL: environment.CARGO_INCREMENTAL ?? "0",
        CARGO_TARGET_DIR: prepared.cache_path,
      },
    });
  } finally {
    if (ownsLease) {
      await releaseBuildCacheLease(lease);
    }
  }
}

function parseCommandLine(argv) {
  if (argv[0] !== "--" || typeof argv[1] !== "string" || argv[1].length === 0) {
    throw new Error("usage: birdcode_cached_command.mjs -- <command> [args...]");
  }
  return { command: argv[1], args: argv.slice(2) };
}

async function main() {
  const result = await runCachedCommand(parseCommandLine(process.argv.slice(2)));
  if (result.signal) {
    process.stderr.write(`Cached command terminated by ${result.signal}\n`);
  }
  process.exitCode = result.status;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
