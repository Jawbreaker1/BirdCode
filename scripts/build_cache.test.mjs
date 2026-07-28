import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  CARGO_CACHE_TAG,
  MARKER_NAME,
  cleanStaleCache,
  inspectCache,
  prepareCache,
  resolveCachePath,
} from "./build_cache.mjs";

const HOUR_MS = 3_600_000;
const scriptsRoot = path.dirname(fileURLToPath(import.meta.url));

async function temporaryRoot(context) {
  const root = await mkdtemp(path.join(os.tmpdir(), "birdcode-build-cache-test-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

test("one prepared cache is reused instead of allocating per-agent targets", async (context) => {
  const root = await temporaryRoot(context);
  const cachePath = path.join(root, "shared-target");
  const first = await prepareCache({ cachePath, minFreeBytes: 0, nowUnixMs: 1_000_000_000_000 });
  await writeFile(path.join(cachePath, "compiled-artifact"), "kept");
  const second = await prepareCache({
    cachePath,
    minFreeBytes: 0,
    nowUnixMs: 1_000_000_000_000 + HOUR_MS,
  });

  assert.equal(first.cache_path, cachePath);
  assert.equal(second.cache_path, cachePath);
  assert.equal(await readFile(path.join(cachePath, "compiled-artifact"), "utf8"), "kept");
  const inspection = await inspectCache({
    cachePath,
    nowUnixMs: 1_000_000_000_000 + HOUR_MS,
  });
  assert.equal(inspection.valid, true);
  assert.equal(inspection.age_hours, 0);
});

test("a valid marker-only cache is upgraded without losing compiled artifacts", async (context) => {
  const root = await temporaryRoot(context);
  const cachePath = path.join(root, "shared-target");
  await prepareCache({ cachePath, minFreeBytes: 0, nowUnixMs: 1_000_000_000_000 });
  await writeFile(path.join(cachePath, "compiled-artifact"), "kept");
  await rm(path.join(cachePath, CARGO_CACHE_TAG));

  await prepareCache({
    cachePath,
    minFreeBytes: 0,
    nowUnixMs: 1_000_000_000_000 + HOUR_MS,
  });

  assert.equal(await readFile(path.join(cachePath, "compiled-artifact"), "utf8"), "kept");
  assert.equal((await inspectCache({ cachePath })).valid, true);
});

test("marker and Cargo tag contracts reject appended or unknown content", async (context) => {
  const root = await temporaryRoot(context);
  const markerCache = path.join(root, "marker-cache");
  await prepareCache({ cachePath: markerCache, minFreeBytes: 0 });
  const markerPath = path.join(markerCache, MARKER_NAME);
  const marker = JSON.parse(await readFile(markerPath, "utf8"));
  marker.unexpected = true;
  await writeFile(markerPath, `${JSON.stringify(marker)}\n`);
  await assert.rejects(
    inspectCache({ cachePath: markerCache }),
    /marker does not match its closed contract/,
  );

  const tagCache = path.join(root, "tag-cache");
  await prepareCache({ cachePath: tagCache, minFreeBytes: 0 });
  const tagPath = path.join(tagCache, CARGO_CACHE_TAG);
  const tag = await readFile(tagPath, "utf8");
  await writeFile(tagPath, `${tag}unexpected\n`);
  await assert.rejects(
    inspectCache({ cachePath: tagCache }),
    /tag does not match its closed contract/,
  );
});

test("stale cleanup is dry-run by default and deletes only after apply", async (context) => {
  const root = await temporaryRoot(context);
  const cachePath = path.join(root, "shared-target");
  const createdAt = 1_000_000_000_000;
  await prepareCache({ cachePath, minFreeBytes: 0, nowUnixMs: createdAt });

  const dryRun = await cleanStaleCache({
    cachePath,
    staleHours: 72,
    nowUnixMs: createdAt + 73 * HOUR_MS,
  });
  assert.equal(dryRun.action, "would_delete");
  assert.equal((await inspectCache({ cachePath })).exists, true);

  const applied = await cleanStaleCache({
    apply: true,
    cachePath,
    staleHours: 72,
    nowUnixMs: createdAt + 73 * HOUR_MS,
  });
  assert.equal(applied.action, "deleted");
  assert.equal((await inspectCache({ cachePath })).exists, false);
});

test("preparing a stale cache reuses it and never performs implicit deletion", async (context) => {
  const root = await temporaryRoot(context);
  const cachePath = path.join(root, "shared-target");
  const createdAt = 1_000_000_000_000;
  await prepareCache({ cachePath, minFreeBytes: 0, nowUnixMs: createdAt });
  await writeFile(path.join(cachePath, "compiled-artifact"), "preserved");

  const prepared = await prepareCache({
    cachePath,
    minFreeBytes: 0,
    staleHours: 72,
    nowUnixMs: createdAt + 73 * HOUR_MS,
  });

  assert.equal(prepared.prior_cleanup, "stale_reused");
  assert.equal(await readFile(path.join(cachePath, "compiled-artifact"), "utf8"), "preserved");
});

test("unmarked directories and symbolic links are never adopted or removed", async (context) => {
  const root = await temporaryRoot(context);
  const unmarked = path.join(root, "unmarked");
  await mkdir(unmarked);
  await writeFile(path.join(unmarked, "source.txt"), "preserve");
  await assert.rejects(
    prepareCache({ cachePath: unmarked, minFreeBytes: 0 }),
    /build cache marker|build cache markers/,
  );
  assert.equal(await readFile(path.join(unmarked, "source.txt"), "utf8"), "preserve");

  const actual = path.join(root, "actual");
  const linked = path.join(root, "linked");
  await prepareCache({ cachePath: actual, minFreeBytes: 0 });
  await symlink(actual, linked);
  await assert.rejects(cleanStaleCache({ apply: true, cachePath: linked, staleHours: 0 }), /real directory/);
  assert.equal((await inspectCache({ cachePath: actual })).exists, true);
});

test("the Cargo wrapper injects the one configured target without compiling", async (context) => {
  const root = await temporaryRoot(context);
  const cachePath = path.join(root, "shared-target");
  const observationPath = path.join(root, "cargo-environment.json");
  const fakeCargo = [
    "-e",
    `require('node:fs').writeFileSync(${JSON.stringify(observationPath)}, JSON.stringify({target: process.env.CARGO_TARGET_DIR, incremental: process.env.CARGO_INCREMENTAL}))`,
  ];
  const result = spawnSync(process.execPath, [path.join(scriptsRoot, "birdcode_cargo.mjs"), ...fakeCargo], {
    env: {
      ...process.env,
      BIRDCODE_CARGO_BIN: process.execPath,
      BIRDCODE_CARGO_TARGET_DIR: cachePath,
    },
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(await readFile(observationPath, "utf8")), {
    target: cachePath,
    incremental: "0",
  });
});

test("cache path rejects a filesystem root and low free space fails before Cargo", async (context) => {
  assert.throws(() => resolveCachePath({ BIRDCODE_CARGO_TARGET_DIR: path.parse(process.cwd()).root }), /filesystem root/);
  const root = await temporaryRoot(context);
  await assert.rejects(
    prepareCache({
      cachePath: path.join(root, "shared-target"),
      minFreeBytes: Number.MAX_SAFE_INTEGER,
    }),
    /Refusing Cargo build/,
  );
  const marker = JSON.parse(await readFile(path.join(root, "shared-target", MARKER_NAME), "utf8"));
  assert.equal(marker.kind, "birdcode_cargo_target");
});

test("desktop build scripts never allocate a repository-local Cargo target", async () => {
  const repositoryRoot = path.dirname(scriptsRoot);
  const desktopScripts = [
    "apps/desktop/scripts/prepare-daemon.sh",
    "apps/desktop/scripts/tauri-dev.sh",
    "apps/desktop/scripts/tauri-build.sh",
  ];

  for (const relativePath of desktopScripts) {
    const source = await readFile(path.join(repositoryRoot, relativePath), "utf8");
    assert.doesNotMatch(source, /repository_root\/target/u, relativePath);
    assert.match(source, /scripts\/build_cache\.mjs/u, relativePath);
  }
});
