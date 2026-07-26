import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  access,
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const EVALUATOR = join(REPOSITORY_ROOT, "scripts/codegen_calibration.mjs");
const EVALUATOR_V2 = join(REPOSITORY_ROOT, "scripts/codegen_calibration_v2.mjs");
const FIXTURE = join(REPOSITORY_ROOT, "evals/codegen/literal-stream-v1");
const PROMPT_MANIFEST = join(
  REPOSITORY_ROOT,
  "prompts/codegen-calibration-literal-stream/1.0.0/manifest.json",
);
const WORKSPACE_PREFIX = "birdcode-codegen-calibration-";
const V2_SHA256 = "63beaa356d286674194fd02086197a61a6ac3b8b0ba5f378270acb41a9934a28";

const PASSING_SOURCE = `/// The absolute position of a literal match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiteralMatch {
    /// The zero-based byte offset in the logical input stream.
    pub offset: u64,
}

/// The outcome of a literal search.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiteralSearchResult {
    /// Matches retained in ascending offset order.
    pub matches: Vec<LiteralMatch>,
    /// Whether a match exists beyond those retained.
    pub truncated: bool,
    /// The number of input bytes inspected.
    pub bytes_scanned: u64,
}

/// An error that prevents a literal search from completing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiteralSearchError {
    /// The requested literal is empty.
    EmptyNeedle,
    /// No matches may be retained.
    ZeroMatchLimit,
    /// The consumed byte count cannot be represented by a \`u64\`.
    OffsetOverflow,
}

/// Searches byte chunks as one logical stream for a literal byte sequence.
///
/// # Errors
///
/// Returns [\`LiteralSearchError::EmptyNeedle\`] for an empty \`needle\`,
/// [\`LiteralSearchError::ZeroMatchLimit\`] for a zero \`max_matches\`, and
/// [\`LiteralSearchError::OffsetOverflow\`] if the consumed byte count overflows.
pub fn search_literal_chunks<'a, I>(
    chunks: I,
    needle: &[u8],
    max_matches: usize,
) -> Result<LiteralSearchResult, LiteralSearchError>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    if needle.is_empty() {
        return Err(LiteralSearchError::EmptyNeedle);
    }
    if max_matches == 0 {
        return Err(LiteralSearchError::ZeroMatchLimit);
    }

    let mut prefix = vec![0_usize; needle.len()];
    let mut prefix_length = 0_usize;
    for (index, &byte) in needle.iter().enumerate().skip(1) {
        while prefix_length > 0 && byte != needle[prefix_length] {
            prefix_length = prefix[prefix_length - 1];
        }
        if byte == needle[prefix_length] {
            prefix_length += 1;
        }
        prefix[index] = prefix_length;
    }

    let mut matches = Vec::new();
    let mut matched_length = 0_usize;
    let mut bytes_scanned = 0_u64;

    for chunk in chunks {
        for &byte in chunk {
            bytes_scanned = bytes_scanned
                .checked_add(1)
                .ok_or(LiteralSearchError::OffsetOverflow)?;

            while matched_length > 0 && byte != needle[matched_length] {
                matched_length = prefix[matched_length - 1];
            }
            if byte == needle[matched_length] {
                matched_length += 1;
            }

            if matched_length == needle.len() {
                if matches.len() == max_matches {
                    return Ok(LiteralSearchResult {
                        matches,
                        truncated: true,
                        bytes_scanned,
                    });
                }

                let needle_length =
                    u64::try_from(needle.len()).map_err(|_| LiteralSearchError::OffsetOverflow)?;
                let offset = bytes_scanned
                    .checked_sub(needle_length)
                    .ok_or(LiteralSearchError::OffsetOverflow)?;
                matches.push(LiteralMatch { offset });
                matched_length = prefix[matched_length - 1];
            }
        }
    }

    Ok(LiteralSearchResult {
        matches,
        truncated: false,
        bytes_scanned,
    })
}
`;

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

function candidateEnvelope(content) {
  return {
    schema_version: 1,
    fixture_id: "literal-stream-v1",
    files: [{ path: "src/lib.rs", content }],
  };
}

function encodeCandidate(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
}

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function makeCase() {
  const root = await mkdtemp(join(tmpdir(), "birdcode-codegen-calibration-test-"));
  const runtimeTmp = join(root, "runtime-tmp");
  await mkdir(runtimeTmp);
  return {
    root,
    runtimeTmp,
    candidate: join(root, "candidate.json"),
    report: join(root, "report.json"),
  };
}

async function runEvaluator(paths, options = {}) {
  const timeoutMs = options.timeoutMs ?? 30_000;
  const arguments_ = [
    EVALUATOR,
    "--fixture",
    FIXTURE,
    "--candidate",
    paths.candidate,
    "--report",
    paths.report,
    "--timeout-ms",
    String(timeoutMs),
  ];
  const started = process.hrtime.bigint();
  return await new Promise((resolveResult, rejectResult) => {
    const child = spawn(process.execPath, arguments_, {
      cwd: REPOSITORY_ROOT,
      env: {
        ...process.env,
        TMPDIR: paths.runtimeTmp,
        ...options.environment,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (bytes) => stdout.push(bytes));
    child.stderr.on("data", (bytes) => stderr.push(bytes));
    const outerTimer = setTimeout(() => child.kill("SIGKILL"), options.outerTimeoutMs ?? 90_000);
    child.once("error", (error) => {
      clearTimeout(outerTimer);
      rejectResult(error);
    });
    child.once("close", (code, signal) => {
      clearTimeout(outerTimer);
      resolveResult({
        code,
        signal,
        elapsedMs: Number((process.hrtime.bigint() - started) / 1_000_000n),
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      });
    });
  });
}

async function readReport(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function assertWorkspaceRemoved(runtimeTmp) {
  const entries = await readdir(runtimeTmp);
  assert.deepEqual(
    entries.filter((entry) => entry.startsWith(WORKSPACE_PREFIX)),
    [],
  );
}

async function installSentinelCargo(root, marker, body) {
  const binaryDirectory = join(root, "bin");
  await mkdir(binaryDirectory);
  const cargo = join(binaryDirectory, "cargo");
  await writeFile(
    cargo,
    body ??
      `#!/usr/bin/env node\nrequire("node:fs").writeFileSync(${JSON.stringify(marker)}, "invoked");\nprocess.exit(97);\n`,
  );
  await chmod(cargo, 0o700);
  return `${binaryDirectory}${delimiter}${process.env.PATH ?? ""}`;
}

test("preserves the exact historical evaluator v2 bytes", async () => {
  assert.equal(sha256(await readFile(EVALUATOR_V2)), V2_SHA256);
});

test("rejects malformed, oversized, and extra-file candidates before Cargo", async (context) => {
  const cases = [
    { name: "malformed JSON", bytes: Buffer.from("{"), kind: "invalid_candidate_json" },
    {
      name: "invalid UTF-8",
      bytes: Buffer.from([0xff]),
      kind: "invalid_candidate_encoding",
    },
    {
      name: "oversized envelope",
      bytes: Buffer.alloc(128 * 1024 + 1, 0x20),
      kind: "candidate_size",
    },
    {
      name: "oversized source",
      bytes: encodeCandidate(candidateEnvelope("x".repeat(64 * 1024 + 1))),
      kind: "source_size",
    },
    {
      name: "extra file",
      bytes: encodeCandidate({
        ...candidateEnvelope(PASSING_SOURCE),
        files: [
          { path: "src/lib.rs", content: PASSING_SOURCE },
          { path: "src/extra.rs", content: "" },
        ],
      }),
      kind: "invalid_candidate_shape",
    },
  ];

  for (const fixtureCase of cases) {
    await context.test(fixtureCase.name, async () => {
      const paths = await makeCase();
      try {
        const marker = join(paths.root, "cargo-invoked");
        const path = await installSentinelCargo(paths.root, marker);
        await writeFile(paths.candidate, fixtureCase.bytes);
        const result = await runEvaluator(paths, { environment: { PATH: path } });
        assert.equal(result.code, 1);
        assert.equal(await exists(marker), false);
        const report = await readReport(paths.report);
        assert.equal(report.status, "setup_failed");
        assert.equal(report.failure.kind, fixtureCase.kind);
        assert.equal((await stat(paths.report)).mode & 0o777, 0o600);
        await assertWorkspaceRemoved(paths.runtimeTmp);
      } finally {
        await rm(paths.root, { recursive: true, force: true });
      }
    });
  }
});

test("refuses an existing report before reading or executing a candidate", async () => {
  const paths = await makeCase();
  try {
    const marker = join(paths.root, "cargo-invoked");
    const path = await installSentinelCargo(paths.root, marker);
    const original = Buffer.from("immutable existing report\n");
    await writeFile(paths.report, original);
    await writeFile(paths.candidate, encodeCandidate(candidateEnvelope(PASSING_SOURCE)));

    const result = await runEvaluator(paths, { environment: { PATH: path } });
    assert.equal(result.code, 1);
    assert.match(result.stderr, /codegen calibration report_exists:/u);
    assert.deepEqual(await readFile(paths.report), original);
    assert.equal(await exists(marker), false);
    await assertWorkspaceRemoved(paths.runtimeTmp);
  } finally {
    await rm(paths.root, { recursive: true, force: true });
  }
});

test("passes a screened candidate and binds every retained input hash", async () => {
  const paths = await makeCase();
  try {
    const candidateBytes = encodeCandidate(candidateEnvelope(PASSING_SOURCE));
    await writeFile(paths.candidate, candidateBytes);
    const result = await runEvaluator(paths);
    assert.equal(result.code, 0, result.stderr);

    const reportBytes = await readFile(paths.report);
    const report = JSON.parse(reportBytes);
    const evaluatorBytes = await readFile(EVALUATOR);
    const taskBytes = await readFile(join(FIXTURE, "task.md"));
    const acceptanceBytes = await readFile(join(FIXTURE, "acceptance.rs"));
    const promptBytes = await readFile(PROMPT_MANIFEST);
    assert.equal(report.evaluator, "birdcode.codegen-calibration/3");
    assert.equal(report.status, "passed");
    assert.equal(report.evaluator_sha256, sha256(evaluatorBytes));
    assert.equal(report.candidate_sha256, sha256(candidateBytes));
    assert.equal(report.source_sha256, sha256(Buffer.from(PASSING_SOURCE)));
    assert.equal(report.task_sha256, sha256(taskBytes));
    assert.equal(report.acceptance_sha256, sha256(acceptanceBytes));
    assert.equal(report.prompt_manifest_sha256, sha256(promptBytes));
    assert.equal(report.evaluator_input_encoding, "sorted-key-json-v1");
    assert.deepEqual(report.limits, {
      max_candidate_bytes: 128 * 1024,
      max_source_bytes: 64 * 1024,
      max_command_stdout_bytes: 1024 * 1024,
      max_command_stderr_bytes: 1024 * 1024,
      command_timeout_ms: 30_000,
    });
    assert.equal(
      report.evaluator_input_sha256,
      sha256(
        Buffer.from(
          canonicalJson({
            schema_version: 1,
            evaluator: report.evaluator,
            fixture_id: report.fixture_id,
            evaluator_sha256: report.evaluator_sha256,
            candidate_sha256: report.candidate_sha256,
            source_sha256: report.source_sha256,
            task_sha256: report.task_sha256,
            acceptance_sha256: report.acceptance_sha256,
            prompt_manifest_sha256: report.prompt_manifest_sha256,
            limits: report.limits,
          }),
        ),
      ),
    );
    assert.deepEqual(
      report.commands.map((command) => command.argv),
      [
        ["cargo", "fmt", "--all", "--", "--check"],
        ["cargo", "test", "--offline", "--all-targets"],
        ["cargo", "clippy", "--offline", "--all-targets", "--", "-D", "warnings"],
      ],
    );
    assert.equal(report.commands.every((command) => command.passed), true);
    const terminal = JSON.parse(result.stdout);
    assert.equal(terminal.status, "passed");
    assert.equal(terminal.report_sha256, sha256(reportBytes));
    await assertWorkspaceRemoved(paths.runtimeTmp);
  } finally {
    await rm(paths.root, { recursive: true, force: true });
  }
});

test("binds the configured timeout into the evaluator input digest", async () => {
  const first = await makeCase();
  const second = await makeCase();
  try {
    const candidateBytes = encodeCandidate(candidateEnvelope("pub fn badly_formatted( ){ }\n"));
    await writeFile(first.candidate, candidateBytes);
    await writeFile(second.candidate, candidateBytes);
    const firstResult = await runEvaluator(first, { timeoutMs: 30_000 });
    const secondResult = await runEvaluator(second, { timeoutMs: 31_000 });
    assert.equal(firstResult.code, 1);
    assert.equal(secondResult.code, 1);
    const firstReport = await readReport(first.report);
    const secondReport = await readReport(second.report);
    assert.equal(firstReport.candidate_sha256, secondReport.candidate_sha256);
    assert.equal(firstReport.limits.command_timeout_ms, 30_000);
    assert.equal(secondReport.limits.command_timeout_ms, 31_000);
    assert.notEqual(firstReport.evaluator_input_sha256, secondReport.evaluator_input_sha256);
    await assertWorkspaceRemoved(first.runtimeTmp);
    await assertWorkspaceRemoved(second.runtimeTmp);
  } finally {
    await rm(first.root, { recursive: true, force: true });
    await rm(second.root, { recursive: true, force: true });
  }
});

test("stops after the first formatting or compilation failure", async (context) => {
  await context.test("formatting failure", async () => {
    const paths = await makeCase();
    try {
      await writeFile(
        paths.candidate,
        encodeCandidate(candidateEnvelope("pub fn badly_formatted( ){ }\n")),
      );
      const result = await runEvaluator(paths);
      assert.equal(result.code, 1);
      const report = await readReport(paths.report);
      assert.equal(report.status, "failed");
      assert.deepEqual(report.commands.map((command) => command.argv[1]), ["fmt"]);
      assert.equal(report.commands[0].passed, false);
      await assertWorkspaceRemoved(paths.runtimeTmp);
    } finally {
      await rm(paths.root, { recursive: true, force: true });
    }
  });

  await context.test("compilation failure", async () => {
    const paths = await makeCase();
    try {
      await writeFile(paths.candidate, encodeCandidate(candidateEnvelope("pub fn unrelated() {}\n")));
      const result = await runEvaluator(paths);
      assert.equal(result.code, 1);
      const report = await readReport(paths.report);
      assert.equal(report.status, "failed");
      assert.deepEqual(report.commands.map((command) => command.argv[1]), ["fmt", "test"]);
      assert.equal(report.commands[0].passed, true);
      assert.equal(report.commands[1].passed, false);
      await assertWorkspaceRemoved(paths.runtimeTmp);
    } finally {
      await rm(paths.root, { recursive: true, force: true });
    }
  });
});

test("spawn failure returns promptly and removes the candidate workspace", async () => {
  const paths = await makeCase();
  try {
    await writeFile(paths.candidate, encodeCandidate(candidateEnvelope(PASSING_SOURCE)));
    const result = await runEvaluator(paths, {
      environment: { PATH: join(paths.root, "missing-bin") },
      timeoutMs: 300_000,
      outerTimeoutMs: 8_000,
    });
    assert.equal(result.code, 1);
    assert.equal(result.elapsedMs < 5_000, true, `spawn failure took ${result.elapsedMs} ms`);
    const report = await readReport(paths.report);
    assert.equal(report.status, "setup_failed");
    assert.equal(report.failure.kind, "infrastructure");
    await assertWorkspaceRemoved(paths.runtimeTmp);
  } finally {
    await rm(paths.root, { recursive: true, force: true });
  }
});

test("passes only the documented environment allowlist to Cargo", async () => {
  const paths = await makeCase();
  try {
    const marker = join(paths.root, "unused-marker");
    const body = `#!/usr/bin/env node
process.stdout.write(JSON.stringify({
  allowedPath: typeof process.env.PATH === "string",
  forbiddenSecret: process.env.BIRDCODE_EVALUATOR_FORBIDDEN_SECRET ?? null,
}));
process.exit(91);
`;
    const path = await installSentinelCargo(paths.root, marker, body);
    await writeFile(paths.candidate, encodeCandidate(candidateEnvelope(PASSING_SOURCE)));
    const result = await runEvaluator(paths, {
      environment: {
        BIRDCODE_EVALUATOR_FORBIDDEN_SECRET: "must-not-cross-boundary",
        PATH: path,
      },
    });
    assert.equal(result.code, 1);
    const report = await readReport(paths.report);
    assert.deepEqual(JSON.parse(report.commands[0].stdout), {
      allowedPath: true,
      forbiddenSecret: null,
    });
    assert.deepEqual(report.environment.subprocess_environment_allowlist, [
      "PATH",
      "HOME",
      "CARGO_HOME",
      "RUSTUP_HOME",
      "TMPDIR",
      "DEVELOPER_DIR",
      "SDKROOT",
      "MACOSX_DEPLOYMENT_TARGET",
    ]);
    await assertWorkspaceRemoved(paths.runtimeTmp);
  } finally {
    await rm(paths.root, { recursive: true, force: true });
  }
});

test("retains at most one MiB from each command output stream", async () => {
  const paths = await makeCase();
  try {
    const marker = join(paths.root, "unused-marker");
    const body = `#!/usr/bin/env node
process.stdout.write(Buffer.alloc(1024 * 1024 + 4096, "x"));
process.stderr.write(Buffer.alloc(1024 * 1024 + 4096, "y"));
process.exitCode = 92;
`;
    const path = await installSentinelCargo(paths.root, marker, body);
    await writeFile(paths.candidate, encodeCandidate(candidateEnvelope(PASSING_SOURCE)));
    const result = await runEvaluator(paths, { environment: { PATH: path } });
    assert.equal(result.code, 1);
    const report = await readReport(paths.report);
    const command = report.commands[0];
    assert.equal(Buffer.byteLength(command.stdout), 1024 * 1024);
    assert.equal(Buffer.byteLength(command.stderr), 1024 * 1024);
    assert.equal(command.stdout_truncated, true);
    assert.equal(command.stderr_truncated, true);
    await assertWorkspaceRemoved(paths.runtimeTmp);
  } finally {
    await rm(paths.root, { recursive: true, force: true });
  }
});

test(
  "timeout kills the detached Cargo process group and removes its workspace",
  { skip: process.platform === "win32" },
  async () => {
    const paths = await makeCase();
    try {
      const marker = join(paths.root, "escaped-grandchild");
      const body = `#!/bin/sh\n(sleep 2; touch ${JSON.stringify(marker)}) &\nsleep 10\n`;
      const path = await installSentinelCargo(paths.root, marker, body);
      await writeFile(paths.candidate, encodeCandidate(candidateEnvelope(PASSING_SOURCE)));
      const result = await runEvaluator(paths, {
        environment: { PATH: path },
        timeoutMs: 1_000,
      });
      assert.equal(result.code, 1);
      const report = await readReport(paths.report);
      assert.equal(report.commands.length, 1);
      assert.equal(report.commands[0].timed_out, true);
      await delay(2_200);
      assert.equal(await exists(marker), false);
      await assertWorkspaceRemoved(paths.runtimeTmp);
    } finally {
      await rm(paths.root, { recursive: true, force: true });
    }
  },
);
