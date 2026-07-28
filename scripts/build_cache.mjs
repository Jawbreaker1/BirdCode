import { randomUUID } from "node:crypto";
import { lstat, mkdir, readFile, realpath, rename, rm, statfs, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

export const CACHE_SCHEMA_VERSION = 1;
export const DEFAULT_STALE_HOURS = 72;
export const DEFAULT_MIN_FREE_BYTES = 20 * 1024 * 1024 * 1024;
export const MARKER_NAME = ".birdcode-build-cache-v1.json";
export const CARGO_CACHE_TAG = "CACHEDIR.TAG";

const CARGO_CACHE_SIGNATURE = "Signature: 8a477f597d28d172789f06886806bc55";
const CARGO_CACHE_TAG_BYTES = `${CARGO_CACHE_SIGNATURE}\n# This file is a cache directory tag created by BirdCode.\n`;

export function resolveCachePath(environment = process.env) {
  const configured = environment.BIRDCODE_CARGO_TARGET_DIR;
  const candidate = configured ?? path.join(os.tmpdir(), "birdcode-cargo-target-v1");
  const absolute = path.resolve(candidate);
  if (absolute === path.parse(absolute).root) {
    throw new Error("BirdCode build cache cannot be a filesystem root");
  }
  return absolute;
}

function markerPath(cachePath) {
  return path.join(cachePath, MARKER_NAME);
}

function cacheTagPath(cachePath) {
  return path.join(cachePath, CARGO_CACHE_TAG);
}

function validMarker(value) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.keys(value).length === 4
    && Object.hasOwn(value, "schema_version")
    && Object.hasOwn(value, "kind")
    && Object.hasOwn(value, "created_at_unix_ms")
    && Object.hasOwn(value, "last_used_at_unix_ms")
    && value.schema_version === CACHE_SCHEMA_VERSION
    && value.kind === "birdcode_cargo_target"
    && Number.isSafeInteger(value.created_at_unix_ms)
    && Number.isSafeInteger(value.last_used_at_unix_ms)
    && value.created_at_unix_ms > 0
    && value.last_used_at_unix_ms >= value.created_at_unix_ms;
}

async function readValidatedMarkerDocument(cachePath) {
  const directory = await lstat(cachePath);
  if (!directory.isDirectory() || directory.isSymbolicLink()) {
    throw new Error(`BirdCode build cache is not a real directory: ${cachePath}`);
  }
  let markerStat;
  try {
    markerStat = await lstat(markerPath(cachePath));
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new Error(`BirdCode build cache marker is missing: ${cachePath}`);
    }
    throw error;
  }
  if (!markerStat.isFile() || markerStat.isSymbolicLink()) {
    throw new Error(`BirdCode build cache marker is unsafe: ${cachePath}`);
  }
  const rawMarker = await readFile(markerPath(cachePath), "utf8");
  let marker;
  try {
    marker = JSON.parse(rawMarker);
  } catch {
    throw new Error(`BirdCode build cache marker is invalid JSON: ${cachePath}`);
  }
  if (!validMarker(marker)) {
    throw new Error(`BirdCode build cache marker does not match its closed contract: ${cachePath}`);
  }
  return marker;
}

async function readValidatedMarker(cachePath) {
  const marker = await readValidatedMarkerDocument(cachePath);
  let tagStat;
  try {
    tagStat = await lstat(cacheTagPath(cachePath));
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new Error(`Cargo cache tag is missing from BirdCode build cache: ${cachePath}`);
    }
    throw error;
  }
  if (!tagStat.isFile() || tagStat.isSymbolicLink()) {
    throw new Error(`Cargo cache tag is unsafe: ${cachePath}`);
  }
  const rawTag = await readFile(cacheTagPath(cachePath), "utf8");
  if (rawTag !== CARGO_CACHE_TAG_BYTES) {
    throw new Error(`Cargo cache tag does not match its closed contract: ${cachePath}`);
  }
  return marker;
}

async function migrateMarkerOnlyCache(cachePath) {
  try {
    await lstat(cachePath);
  } catch (error) {
    if (error?.code === "ENOENT") {
      return;
    }
    throw error;
  }
  await readValidatedMarkerDocument(cachePath);
  try {
    await writeFile(cacheTagPath(cachePath), CARGO_CACHE_TAG_BYTES, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
    });
  } catch (error) {
    if (error?.code !== "EEXIST") {
      throw error;
    }
  }
  await readValidatedMarker(cachePath);
}

async function writeMarker(cachePath, marker) {
  const temporary = path.join(cachePath, `.${MARKER_NAME}.${process.pid}.${randomUUID()}.tmp`);
  await writeFile(temporary, `${JSON.stringify(marker)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
  await rename(temporary, markerPath(cachePath));
}

export async function inspectCache({ cachePath = resolveCachePath(), nowUnixMs = Date.now() } = {}) {
  try {
    await lstat(cachePath);
  } catch (error) {
    if (error?.code === "ENOENT") {
      return { cache_path: cachePath, exists: false, valid: false, age_hours: null, marker: null };
    }
    throw error;
  }
  const marker = await readValidatedMarker(cachePath);
  return {
    cache_path: cachePath,
    exists: true,
    valid: true,
    age_hours: (nowUnixMs - marker.last_used_at_unix_ms) / 3_600_000,
    marker,
  };
}

export async function cleanStaleCache({
  apply = false,
  cachePath = resolveCachePath(),
  staleHours = DEFAULT_STALE_HOURS,
  nowUnixMs = Date.now(),
} = {}) {
  if (!Number.isFinite(staleHours) || staleHours < 0) {
    throw new Error("staleHours must be a non-negative finite number");
  }
  const inspection = await inspectCache({ cachePath, nowUnixMs });
  const stale = inspection.exists && inspection.age_hours >= staleHours;
  if (apply && stale) {
    await readValidatedMarker(cachePath);
    const parentBefore = await realpath(path.dirname(cachePath));
    if (path.dirname(await realpath(cachePath)) !== parentBefore) {
      throw new Error(`BirdCode build cache escaped its configured parent: ${cachePath}`);
    }
    await rm(cachePath, { recursive: true, force: false });
  }
  return {
    ...inspection,
    stale,
    action: stale ? (apply ? "deleted" : "would_delete") : "kept",
  };
}

export async function prepareCache({
  cachePath = resolveCachePath(),
  staleHours = DEFAULT_STALE_HOURS,
  minFreeBytes = DEFAULT_MIN_FREE_BYTES,
  nowUnixMs = Date.now(),
} = {}) {
  if (!Number.isFinite(staleHours) || staleHours < 0) {
    throw new Error("staleHours must be a non-negative finite number");
  }
  await migrateMarkerOnlyCache(cachePath);
  const beforePrepare = await inspectCache({ cachePath, nowUnixMs });
  const priorCleanup = beforePrepare.exists && beforePrepare.age_hours >= staleHours
    ? "stale_reused"
    : "kept";
  let createdAt = nowUnixMs;
  if (beforePrepare.exists) {
    createdAt = beforePrepare.marker.created_at_unix_ms;
  } else {
    await mkdir(cachePath, { recursive: true, mode: 0o700 });
    const directory = await lstat(cachePath);
    if (!directory.isDirectory() || directory.isSymbolicLink()) {
      throw new Error(`BirdCode build cache is not a real directory: ${cachePath}`);
    }
    try {
      await writeFile(cacheTagPath(cachePath), CARGO_CACHE_TAG_BYTES, {
        encoding: "utf8",
        mode: 0o600,
        flag: "wx",
      });
    } catch (error) {
      if (error?.code !== "EEXIST") {
        throw error;
      }
      const existingTag = await readFile(cacheTagPath(cachePath), "utf8");
      if (existingTag !== CARGO_CACHE_TAG_BYTES) {
        throw new Error(`BirdCode build cache tag is unsafe: ${cachePath}`);
      }
    }
  }
  await writeMarker(cachePath, {
    schema_version: CACHE_SCHEMA_VERSION,
    kind: "birdcode_cargo_target",
    created_at_unix_ms: createdAt,
    last_used_at_unix_ms: nowUnixMs,
  });

  const filesystem = await statfs(cachePath, { bigint: true });
  const availableBytes = filesystem.bavail * filesystem.bsize;
  if (availableBytes < BigInt(minFreeBytes)) {
    throw new Error(
      `Refusing Cargo build: only ${availableBytes} bytes are available; ${minFreeBytes} required`,
    );
  }
  return { cache_path: cachePath, available_bytes: availableBytes, prior_cleanup: priorCleanup };
}

function parseArguments(argv) {
  const [command = "inspect", ...rest] = argv;
  let apply = false;
  let staleHours = DEFAULT_STALE_HOURS;
  for (let index = 0; index < rest.length; index += 1) {
    const argument = rest[index];
    if (argument === "--apply") {
      apply = true;
    } else if (argument === "--stale-hours") {
      staleHours = Number(rest[index + 1]);
      index += 1;
    } else {
      throw new Error(`Unknown build-cache argument: ${argument}`);
    }
  }
  return { command, apply, staleHours };
}

async function main() {
  const { command, apply, staleHours } = parseArguments(process.argv.slice(2));
  let result;
  if (command === "inspect") {
    result = await inspectCache();
  } else if (command === "clean") {
    result = await cleanStaleCache({ apply, staleHours });
  } else if (command === "prepare") {
    result = await prepareCache({ staleHours });
  } else if (command === "path") {
    process.stdout.write(`${resolveCachePath()}\n`);
    return;
  } else {
    throw new Error(`Unknown build-cache command: ${command}`);
  }
  process.stdout.write(`${JSON.stringify(result, (_, value) => typeof value === "bigint" ? value.toString() : value)}\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
