import assert from "node:assert/strict";
import test from "node:test";
import {
  countSourceLines,
  evaluateRepositoryHealth,
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
