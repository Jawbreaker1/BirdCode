import { randomUUID } from "node:crypto";
import {
  lstat,
  mkdir,
  opendir,
  readFile,
  realpath,
  rename,
  rm,
  statfs,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

export const CACHE_SCHEMA_VERSION = 1;
export const DEFAULT_STALE_HOURS = 72;
export const DEFAULT_MIN_FREE_BYTES = 20 * 1024 * 1024 * 1024;
export const DEFAULT_MAX_CACHE_BYTES = 30n * 1024n * 1024n * 1024n;
export const DEFAULT_SCAN_MAX_ENTRIES = 250_000;
export const DEFAULT_SCAN_MAX_DURATION_MS = 10_000;
export const MARKER_NAME = ".birdcode-build-cache-v1.json";
export const CARGO_CACHE_TAG = "CACHEDIR.TAG";
export const CONTROL_MARKER_NAME = ".birdcode-build-cache-control-v1.json";
export const CONTROL_LEASES_NAME = "leases";
export const CONTROL_CLEANUP_GATE_NAME = "cleanup-gate";

const CARGO_CACHE_SIGNATURE = "Signature: 8a477f597d28d172789f06886806bc55";
const CARGO_CACHE_TAG_BYTES = `${CARGO_CACHE_SIGNATURE}\n# This file is a cache directory tag created by BirdCode.\n`;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export function resolveCachePath(environment = process.env) {
  const configured = environment.BIRDCODE_CARGO_TARGET_DIR;
  const candidate = configured ?? path.join(os.tmpdir(), "birdcode-cargo-target-v1");
  const absolute = path.resolve(candidate);
  if (absolute === path.parse(absolute).root) {
    throw new Error("BirdCode build cache cannot be a filesystem root");
  }
  return absolute;
}

export function resolveCacheControlPath(cachePath = resolveCachePath()) {
  const absolute = path.resolve(cachePath);
  if (absolute === path.parse(absolute).root) {
    throw new Error("BirdCode build cache cannot be a filesystem root");
  }
  return path.join(path.dirname(absolute), `.${path.basename(absolute)}.birdcode-control-v1`);
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

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

async function inspectCacheState({ cachePath, nowUnixMs }) {
  let before;
  try {
    before = await lstat(cachePath, { bigint: true });
  } catch (error) {
    if (error?.code === "ENOENT") {
      return {
        inspection: {
          cache_path: cachePath,
          exists: false,
          valid: false,
          age_hours: null,
          marker: null,
        },
        identity: null,
      };
    }
    throw error;
  }
  const marker = await readValidatedMarker(cachePath);
  const after = await lstat(cachePath, { bigint: true });
  if (!sameIdentity(before, after)) {
    throw new Error(`BirdCode build cache changed while it was inspected: ${cachePath}`);
  }
  return {
    inspection: {
      cache_path: cachePath,
      exists: true,
      valid: true,
      age_hours: (nowUnixMs - marker.last_used_at_unix_ms) / 3_600_000,
      marker,
    },
    identity: after,
  };
}

export async function inspectCache({ cachePath = resolveCachePath(), nowUnixMs = Date.now() } = {}) {
  return (await inspectCacheState({ cachePath, nowUnixMs })).inspection;
}

function incompleteSize(logicalSizeBytes, entriesScanned, reason) {
  return {
    logical_size_bytes: logicalSizeBytes,
    entries_scanned: entriesScanned,
    complete: false,
    incomplete_reason: reason,
  };
}

export async function inspectCacheLogicalSize({
  cachePath = resolveCachePath(),
  maxEntries = DEFAULT_SCAN_MAX_ENTRIES,
  maxDurationMs = DEFAULT_SCAN_MAX_DURATION_MS,
} = {}) {
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 0) {
    throw new Error("maxEntries must be a non-negative safe integer");
  }
  if (!Number.isFinite(maxDurationMs) || maxDurationMs < 0) {
    throw new Error("maxDurationMs must be a non-negative finite number");
  }
  let root;
  try {
    root = await lstat(cachePath, { bigint: true });
  } catch (error) {
    if (error?.code === "ENOENT") {
      return {
        logical_size_bytes: 0n,
        entries_scanned: 0,
        complete: true,
        incomplete_reason: null,
      };
    }
    throw error;
  }
  if (!root.isDirectory() || root.isSymbolicLink()) {
    throw new Error(`BirdCode build cache is not a real directory: ${cachePath}`);
  }

  const startedAt = Date.now();
  const pendingDirectories = [cachePath];
  let logicalSizeBytes = 0n;
  let entriesScanned = 0;
  while (pendingDirectories.length > 0) {
    if (Date.now() - startedAt >= maxDurationMs) {
      return incompleteSize(logicalSizeBytes, entriesScanned, "duration_limit");
    }
    const directoryPath = pendingDirectories.pop();
    try {
      const directory = await opendir(directoryPath);
      for await (const entry of directory) {
        if (entriesScanned >= maxEntries) {
          return incompleteSize(logicalSizeBytes, entriesScanned, "entry_limit");
        }
        if (Date.now() - startedAt >= maxDurationMs) {
          return incompleteSize(logicalSizeBytes, entriesScanned, "duration_limit");
        }
        entriesScanned += 1;
        const entryPath = path.join(directoryPath, entry.name);
        const entryStat = await lstat(entryPath, { bigint: true });
        if (entryStat.isDirectory() && !entryStat.isSymbolicLink()) {
          pendingDirectories.push(entryPath);
        } else if (entryStat.isFile() && !entryStat.isSymbolicLink()) {
          logicalSizeBytes += entryStat.size;
        }
      }
    } catch (error) {
      return incompleteSize(
        logicalSizeBytes,
        entriesScanned,
        `filesystem_${error?.code ?? "error"}`,
      );
    }
  }
  return {
    logical_size_bytes: logicalSizeBytes,
    entries_scanned: entriesScanned,
    complete: true,
    incomplete_reason: null,
  };
}

function controlMarkerBytes(cachePath) {
  return `${JSON.stringify({
    schema_version: CACHE_SCHEMA_VERSION,
    kind: "birdcode_build_cache_control",
    cache_path: path.resolve(cachePath),
  })}\n`;
}

function controlPaths(cachePath) {
  const absoluteCachePath = path.resolve(cachePath);
  const controlPath = resolveCacheControlPath(absoluteCachePath);
  return {
    cachePath: absoluteCachePath,
    controlPath,
    markerPath: path.join(controlPath, CONTROL_MARKER_NAME),
    leasesPath: path.join(controlPath, CONTROL_LEASES_NAME),
    gatePath: path.join(controlPath, CONTROL_CLEANUP_GATE_NAME),
  };
}

async function validateControlDirectory(cachePath) {
  const paths = controlPaths(cachePath);
  const controlStat = await lstat(paths.controlPath);
  if (!controlStat.isDirectory() || controlStat.isSymbolicLink()) {
    throw new Error(`BirdCode build-cache control path is unsafe: ${paths.controlPath}`);
  }
  const markerStat = await lstat(paths.markerPath);
  if (!markerStat.isFile() || markerStat.isSymbolicLink()) {
    throw new Error(`BirdCode build-cache control marker is unsafe: ${paths.markerPath}`);
  }
  if (await readFile(paths.markerPath, "utf8") !== controlMarkerBytes(paths.cachePath)) {
    throw new Error(`BirdCode build-cache control marker does not match its closed contract`);
  }
  const leasesStat = await lstat(paths.leasesPath);
  if (!leasesStat.isDirectory() || leasesStat.isSymbolicLink()) {
    throw new Error(`BirdCode build-cache leases path is unsafe: ${paths.leasesPath}`);
  }
  return paths;
}

async function ensureControlDirectory(cachePath) {
  const paths = controlPaths(cachePath);
  if (await entryExists(paths.controlPath)) {
    return validateControlDirectory(paths.cachePath);
  }
  const temporaryControlPath = `${paths.controlPath}.init-${randomUUID()}`;
  const temporaryMarkerPath = path.join(temporaryControlPath, CONTROL_MARKER_NAME);
  const temporaryLeasesPath = path.join(temporaryControlPath, CONTROL_LEASES_NAME);
  await mkdir(temporaryControlPath, { mode: 0o700 });
  try {
    await writeFile(temporaryMarkerPath, controlMarkerBytes(paths.cachePath), {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
    });
    await mkdir(temporaryLeasesPath, { mode: 0o700 });
    try {
      await rename(temporaryControlPath, paths.controlPath);
    } catch (error) {
      if (error?.code !== "EEXIST" && error?.code !== "ENOTEMPTY") {
        throw error;
      }
    }
  } finally {
    if (await entryExists(temporaryControlPath)) {
      await rm(temporaryControlPath, { recursive: true, force: false });
    }
  }
  return validateControlDirectory(paths.cachePath);
}

async function entryExists(entryPath) {
  try {
    await lstat(entryPath);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

function leaseBytes(cachePath, leaseId) {
  return `${JSON.stringify({
    schema_version: CACHE_SCHEMA_VERSION,
    kind: "birdcode_build_cache_lease",
    cache_path: path.resolve(cachePath),
    lease_id: leaseId,
  })}\n`;
}

function checkedLeaseIdentity(cachePath, leaseId) {
  if (!UUID_PATTERN.test(leaseId ?? "")) {
    throw new Error("BirdCode build-cache lease ID is invalid");
  }
  const paths = controlPaths(cachePath);
  return {
    paths,
    lease: { cache_path: paths.cachePath, lease_id: leaseId },
    leasePath: path.join(paths.leasesPath, `${leaseId}.json`),
  };
}

export async function acquireBuildCacheLease({ cachePath = resolveCachePath() } = {}) {
  const paths = await ensureControlDirectory(cachePath);
  if (await entryExists(paths.gatePath)) {
    throw new Error("BirdCode build-cache cleanup is active");
  }
  const leaseId = randomUUID();
  const identity = checkedLeaseIdentity(paths.cachePath, leaseId);
  await writeFile(identity.leasePath, leaseBytes(paths.cachePath, leaseId), {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  if (await entryExists(paths.gatePath)) {
    await rm(identity.leasePath, { force: false });
    throw new Error("BirdCode build-cache cleanup became active during lease acquisition");
  }
  return identity.lease;
}

export async function validateBuildCacheLease({
  cachePath = resolveCachePath(),
  leaseId,
} = {}) {
  const identity = checkedLeaseIdentity(cachePath, leaseId);
  await validateControlDirectory(identity.paths.cachePath);
  const leaseStat = await lstat(identity.leasePath);
  if (!leaseStat.isFile() || leaseStat.isSymbolicLink()) {
    throw new Error("BirdCode build-cache lease is unsafe");
  }
  if (await readFile(identity.leasePath, "utf8") !== leaseBytes(identity.paths.cachePath, leaseId)) {
    throw new Error("BirdCode build-cache lease does not match its closed contract");
  }
  return identity.lease;
}

export async function releaseBuildCacheLease(lease) {
  const validated = await validateBuildCacheLease({
    cachePath: lease?.cache_path,
    leaseId: lease?.lease_id,
  });
  const identity = checkedLeaseIdentity(validated.cache_path, validated.lease_id);
  await rm(identity.leasePath, { force: false });
}

export async function withBuildCacheLease(options, operation) {
  if (typeof operation !== "function") {
    throw new Error("withBuildCacheLease requires an operation");
  }
  const lease = await acquireBuildCacheLease(options);
  try {
    return await operation(lease);
  } finally {
    await releaseBuildCacheLease(lease);
  }
}

async function acquireCleanupGate(cachePath) {
  const paths = await ensureControlDirectory(cachePath);
  const gateId = randomUUID();
  const bytes = `${JSON.stringify({
    schema_version: CACHE_SCHEMA_VERSION,
    kind: "birdcode_build_cache_cleanup_gate",
    cache_path: paths.cachePath,
    gate_id: gateId,
  })}\n`;
  try {
    await writeFile(paths.gatePath, bytes, { encoding: "utf8", mode: 0o600, flag: "wx" });
  } catch (error) {
    if (error?.code === "EEXIST") {
      throw new Error("BirdCode build-cache cleanup is already active");
    }
    throw error;
  }
  return { paths, bytes };
}

async function releaseCleanupGate(gate) {
  const gateStat = await lstat(gate.paths.gatePath);
  if (!gateStat.isFile() || gateStat.isSymbolicLink()) {
    throw new Error("BirdCode build-cache cleanup gate is unsafe");
  }
  if (await readFile(gate.paths.gatePath, "utf8") !== gate.bytes) {
    throw new Error("BirdCode build-cache cleanup gate changed unexpectedly");
  }
  await rm(gate.paths.gatePath, { force: false });
}

async function leasesDirectoryIsBusy(leasesPath) {
  const directory = await opendir(leasesPath);
  try {
    return await directory.read() !== null;
  } finally {
    await directory.close();
  }
}

function maxCacheBytesValue(value) {
  if (
    (typeof value !== "bigint" && (!Number.isSafeInteger(value) || value < 0))
    || (typeof value === "bigint" && value < 0n)
  ) {
    throw new Error("maxCacheBytes must be a non-negative integer");
  }
  return BigInt(value);
}

export async function cleanStaleCache({
  apply = false,
  cachePath = resolveCachePath(),
  staleHours = DEFAULT_STALE_HOURS,
  maxCacheBytes = DEFAULT_MAX_CACHE_BYTES,
  scanMaxEntries = DEFAULT_SCAN_MAX_ENTRIES,
  scanMaxDurationMs = DEFAULT_SCAN_MAX_DURATION_MS,
  nowUnixMs = Date.now(),
} = {}) {
  if (!Number.isFinite(staleHours) || staleHours < 0) {
    throw new Error("staleHours must be a non-negative finite number");
  }
  const byteLimit = maxCacheBytesValue(maxCacheBytes);
  const initial = await inspectCacheState({ cachePath, nowUnixMs });
  const inspection = initial.inspection;
  const size = await inspectCacheLogicalSize({
    cachePath,
    maxEntries: scanMaxEntries,
    maxDurationMs: scanMaxDurationMs,
  });
  const stale = inspection.exists && inspection.age_hours >= staleHours;
  const oversized = inspection.exists && size.logical_size_bytes >= byteLimit;
  const candidate = stale || oversized;
  if (apply && inspection.exists && !size.complete) {
    throw new Error(`Refusing build-cache cleanup because the size scan is incomplete`);
  }
  if (!apply || !candidate) {
    return {
      ...inspection,
      ...size,
      max_cache_bytes: byteLimit,
      stale,
      oversized,
      candidate,
      action: candidate ? "would_delete" : (size.complete ? "kept" : "scan_incomplete"),
    };
  }

  const gate = await acquireCleanupGate(cachePath);
  try {
    if (await leasesDirectoryIsBusy(gate.paths.leasesPath)) {
      throw new Error("Refusing build-cache cleanup while any lease entry exists");
    }
    const current = await inspectCacheState({ cachePath, nowUnixMs });
    if (!current.inspection.exists || !sameIdentity(initial.identity, current.identity)) {
      throw new Error("Refusing build-cache cleanup because the cache identity changed");
    }
    const currentSize = await inspectCacheLogicalSize({
      cachePath,
      maxEntries: scanMaxEntries,
      maxDurationMs: scanMaxDurationMs,
    });
    if (!currentSize.complete) {
      throw new Error("Refusing build-cache cleanup because the revalidation scan is incomplete");
    }
    const currentStale = current.inspection.age_hours >= staleHours;
    const currentOversized = currentSize.logical_size_bytes >= byteLimit;
    if (!currentStale && !currentOversized) {
      return {
        ...current.inspection,
        ...currentSize,
        max_cache_bytes: byteLimit,
        stale: false,
        oversized: false,
        candidate: false,
        action: "kept",
      };
    }
    const finalState = await inspectCacheState({ cachePath, nowUnixMs });
    if (!finalState.inspection.exists || !sameIdentity(current.identity, finalState.identity)) {
      throw new Error("Refusing build-cache cleanup because the cache identity changed");
    }
    const parentBefore = await realpath(path.dirname(cachePath));
    if (path.dirname(await realpath(cachePath)) !== parentBefore) {
      throw new Error(`BirdCode build cache escaped its configured parent: ${cachePath}`);
    }
    const tombstone = path.join(
      path.dirname(path.resolve(cachePath)),
      `.${path.basename(cachePath)}.birdcode-tombstone-${randomUUID()}`,
    );
    await rename(cachePath, tombstone);
    await rm(tombstone, { recursive: true, force: false });
    return {
      ...finalState.inspection,
      ...currentSize,
      max_cache_bytes: byteLimit,
      stale: currentStale,
      oversized: currentOversized,
      candidate: true,
      action: "deleted",
    };
  } finally {
    await releaseCleanupGate(gate);
  }
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
  let maxCacheBytes = DEFAULT_MAX_CACHE_BYTES;
  for (let index = 0; index < rest.length; index += 1) {
    const argument = rest[index];
    if (argument === "--apply") {
      apply = true;
    } else if (argument === "--stale-hours") {
      staleHours = Number(rest[index + 1]);
      index += 1;
    } else if (argument === "--max-bytes") {
      maxCacheBytes = BigInt(rest[index + 1]);
      index += 1;
    } else {
      throw new Error(`Unknown build-cache argument: ${argument}`);
    }
  }
  return { command, apply, staleHours, maxCacheBytes };
}

async function main() {
  const { command, apply, staleHours, maxCacheBytes } = parseArguments(process.argv.slice(2));
  let result;
  if (command === "inspect") {
    result = await inspectCache();
  } else if (command === "clean") {
    result = await cleanStaleCache({ apply, staleHours, maxCacheBytes });
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
