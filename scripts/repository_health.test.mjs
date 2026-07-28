import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  countSourceLines,
  evaluateRepositoryHealth,
  evaluateRepositoryHealthRatchet,
  inspectRepositoryHealth,
  validateRepositoryHealthConfig,
} from "./repository_health.mjs";

function config() {
  return {
    schema_version: 1,
    source_limits: {
      mjs: 8,
      rs: 10,
    },
    debt: [
      {
        path: "src/existing.rs",
        ceiling_lines: 15,
      },
    ],
  };
}

function runGit(root, arguments_) {
  const result = spawnSync("git", arguments_, {
    cwd: root,
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
}

test("line counting handles empty, terminated, and unterminated sources", () => {
  assert.equal(countSourceLines(Buffer.from("")), 0);
  assert.equal(countSourceLines(Buffer.from("one\n")), 1);
  assert.equal(countSourceLines(Buffer.from("one\ntwo")), 2);
  assert.equal(countSourceLines(Buffer.from("one\r\ntwo\r\n")), 2);
});

test("an exact debt ceiling and ordinary small sources pass", () => {
  const report = evaluateRepositoryHealth({
    config: config(),
    files: [
      { path: "scripts/check.mjs", lines: 8 },
      { path: "src/existing.rs", lines: 15 },
      { path: "src/new.rs", lines: 10 },
    ],
  });

  assert.equal(report.healthy, true);
  assert.deepEqual(report.violations, []);
});

test("new growth and growth above an existing ceiling fail", () => {
  const report = evaluateRepositoryHealth({
    config: config(),
    files: [
      { path: "src/existing.rs", lines: 16 },
      { path: "src/new.rs", lines: 11 },
    ],
  });

  assert.equal(report.healthy, false);
  assert.deepEqual(report.violations, [
    "src/existing.rs grew to 16 lines; its debt ceiling is 15",
    "src/new.rs has 11 lines; new source files are limited to 10",
  ]);
});

test("shrinking or removing debt requires ratcheting the checked-in ceiling", () => {
  const shrunk = evaluateRepositoryHealth({
    config: config(),
    files: [{ path: "src/existing.rs", lines: 12 }],
  });
  assert.deepEqual(shrunk.violations, [
    "src/existing.rs shrank to 12 lines; lower its debt ceiling from 15",
  ]);

  const removed = evaluateRepositoryHealth({
    config: config(),
    files: [],
  });
  assert.deepEqual(removed.violations, [
    "src/existing.rs is absent; remove its stale debt ceiling of 15",
  ]);
});

test("a repo-local Cargo target fails even when source ceilings pass", () => {
  const report = evaluateRepositoryHealth({
    config: config(),
    files: [{ path: "src/existing.rs", lines: 15 }],
    legacyTargetExists: true,
  });

  assert.equal(report.healthy, false);
  assert.match(report.violations[0], /repo-local target/);
});

test("invalid or ineffective debt exceptions are rejected", () => {
  const invalid = config();
  invalid.debt.push({
    path: "src/small.rs",
    ceiling_lines: 10,
  });
  assert.throws(
    () => validateRepositoryHealthConfig(invalid),
    /must exceed its default limit/,
  );
});

test("duplicate debt paths and unknown fields are rejected", () => {
  const duplicate = config();
  duplicate.debt.push({
    path: "src/existing.rs",
    ceiling_lines: 16,
  });
  assert.throws(
    () => validateRepositoryHealthConfig(duplicate),
    /duplicate debt ceiling path/,
  );

  const unknown = config();
  unknown.unbounded = true;
  assert.throws(
    () => validateRepositoryHealthConfig(unknown),
    /must contain exactly/,
  );
});

test("the baseline ratchet permits only tighter limits and lower or removed debt", () => {
  const current = config();
  current.source_limits.rs = 9;
  current.source_limits.ts = 8;
  current.debt[0].ceiling_lines = 14;

  assert.deepEqual(
    evaluateRepositoryHealthRatchet({
      baselineConfig: config(),
      currentConfig: current,
    }),
    [],
  );

  current.debt = [];
  assert.deepEqual(
    evaluateRepositoryHealthRatchet({
      baselineConfig: config(),
      currentConfig: current,
    }),
    [],
  );
});

test("the baseline ratchet rejects removed or raised limits", () => {
  const current = config();
  delete current.source_limits.mjs;
  current.source_limits.rs = 14;

  assert.deepEqual(
    evaluateRepositoryHealthRatchet({
      baselineConfig: config(),
      currentConfig: current,
    }),
    [
      "source limit for .mjs was removed",
      "source limit for .rs increased from 10 to 14",
    ],
  );
});

test("the baseline ratchet rejects raised ceilings and new debt exceptions", () => {
  const current = config();
  current.debt[0].ceiling_lines = 50_000;
  current.debt.push({
    path: "src/new-monolith.rs",
    ceiling_lines: 50_000,
  });

  assert.deepEqual(
    evaluateRepositoryHealthRatchet({
      baselineConfig: config(),
      currentConfig: current,
    }),
    [
      "new repository-health debt exception is forbidden: src/new-monolith.rs",
      "src/existing.rs debt ceiling increased from 15 to 50000",
    ],
  );
});

test("repository inspection rejects a self-raised ceiling against committed HEAD", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "birdcode-repository-health-test-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, "config"));
  await mkdir(path.join(root, "src"));
  await writeFile(
    path.join(root, "config/repository-health.v1.json"),
    `${JSON.stringify(config(), null, 2)}\n`,
  );
  await writeFile(path.join(root, "src/existing.rs"), "line\n".repeat(15));
  runGit(root, ["init", "-q"]);
  runGit(root, ["config", "user.email", "repository-health@example.invalid"]);
  runGit(root, ["config", "user.name", "Repository Health Test"]);
  runGit(root, ["add", "config/repository-health.v1.json", "src/existing.rs"]);
  runGit(root, ["commit", "-qm", "baseline"]);

  const raised = config();
  raised.debt[0].ceiling_lines = 16;
  await writeFile(
    path.join(root, "config/repository-health.v1.json"),
    `${JSON.stringify(raised, null, 2)}\n`,
  );
  await writeFile(path.join(root, "src/existing.rs"), "line\n".repeat(16));

  const report = await inspectRepositoryHealth({ root });
  assert.equal(report.healthy, false);
  assert.deepEqual(report.violations, [
    "src/existing.rs debt ceiling increased from 15 to 16",
  ]);
});
