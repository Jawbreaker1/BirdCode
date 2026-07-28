import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import {
  BUILD_CACHE_LEASE_ENV,
  runCachedCommand,
} from "./birdcode_cached_command.mjs";
import {
  acquireBuildCacheLease,
  releaseBuildCacheLease,
  validateBuildCacheLease,
} from "./build_cache.mjs";

async function temporaryRoot(context) {
  const root = await mkdtemp(path.join(os.tmpdir(), "birdcode-cached-command-test-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

async function readWhenPresent(filePath) {
  for (let attempt = 0; attempt < 500; attempt += 1) {
    try {
      return await readFile(filePath, "utf8");
    } catch (error) {
      if (error?.code !== "ENOENT") {
        throw error;
      }
      await delay(10);
    }
  }
  throw new Error(`Timed out waiting for ${filePath}`);
}

function cacheEnvironment(cachePath) {
  const environment = {
    ...process.env,
    BIRDCODE_CARGO_TARGET_DIR: cachePath,
  };
  delete environment[BUILD_CACHE_LEASE_ENV];
  return environment;
}

test("a foreground command holds one cache lease and releases it for every exit status", async (context) => {
  const root = await temporaryRoot(context);
  const cachePath = path.join(root, "shared-target");
  const childSource = `
    const fs = require("node:fs");
    const observationPath = process.argv[1];
    const releasePath = process.argv[2];
    const status = Number(process.argv[3]);
    fs.writeFileSync(observationPath, JSON.stringify({
      leaseId: process.env.BIRDCODE_BUILD_CACHE_LEASE_ID,
      target: process.env.CARGO_TARGET_DIR,
      wrapped: process.env.BIRDCODE_BUILD_CACHE_WRAPPED,
    }));
    const interval = setInterval(() => {
      if (fs.existsSync(releasePath)) {
        clearInterval(interval);
        process.exit(status);
      }
    }, 5);
    setTimeout(() => process.exit(99), 5_000);
  `;

  for (const expectedStatus of [0, 7]) {
    const observationPath = path.join(root, `observation-${expectedStatus}.json`);
    const releasePath = path.join(root, `release-${expectedStatus}`);
    const running = runCachedCommand({
      command: process.execPath,
      args: ["-e", childSource, observationPath, releasePath, String(expectedStatus)],
      environment: cacheEnvironment(cachePath),
    });
    const observation = JSON.parse(await readWhenPresent(observationPath));

    assert.equal(observation.target, cachePath);
    assert.equal(observation.wrapped, "1");
    assert.equal(typeof observation.leaseId, "string");
    await validateBuildCacheLease({
      cachePath,
      leaseId: observation.leaseId,
    });

    await writeFile(releasePath, "");
    assert.equal((await running).status, expectedStatus);
    await assert.rejects(validateBuildCacheLease({
      cachePath,
      leaseId: observation.leaseId,
    }));
  }
});

test("a nested cached command validates but does not release its inherited lease", async (context) => {
  const root = await temporaryRoot(context);
  const cachePath = path.join(root, "shared-target");
  const lease = await acquireBuildCacheLease({ cachePath });

  try {
    const result = await runCachedCommand({
      command: process.execPath,
      args: ["-e", "process.exit(0)"],
      environment: {
        ...cacheEnvironment(cachePath),
        [BUILD_CACHE_LEASE_ENV]: lease.lease_id,
      },
    });
    assert.equal(result.status, 0);
    await validateBuildCacheLease({
      cachePath,
      leaseId: lease.lease_id,
    });
  } finally {
    await releaseBuildCacheLease(lease);
  }
});
