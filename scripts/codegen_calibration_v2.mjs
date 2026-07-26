#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  open,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";

const MAX_CANDIDATE_BYTES = 128 * 1024;
const MAX_SOURCE_BYTES = 64 * 1024;
const MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 60_000;
const FIXTURE_ID = "literal-stream-v1";
const CANDIDATE_PATH = "src/lib.rs";
const EVALUATOR_ID = "birdcode.codegen-calibration/2";
const SUBPROCESS_ENVIRONMENT_ALLOWLIST = [
  "PATH",
  "HOME",
  "CARGO_HOME",
  "RUSTUP_HOME",
  "TMPDIR",
  "DEVELOPER_DIR",
  "SDKROOT",
  "MACOSX_DEPLOYMENT_TARGET",
];

const CARGO_MANIFEST = `[package]
name = "candidate"
version = "0.0.0"
edition = "2024"
publish = false

[lib]
path = "src/lib.rs"

[[test]]
name = "acceptance"
path = "tests/acceptance.rs"

[workspace]

[lints.rust]
unsafe_code = "forbid"

[lints.clippy]
all = "warn"
pedantic = "warn"
`;

class CalibrationError extends Error {
  constructor(kind, message) {
    super(message);
    this.kind = kind;
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function exactKeys(value, expected, field) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new CalibrationError("invalid_candidate_shape", `${field} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((entry, index) => entry !== wanted[index])) {
    throw new CalibrationError(
      "invalid_candidate_shape",
      `${field} has fields ${JSON.stringify(actual)} instead of ${JSON.stringify(wanted)}`,
    );
  }
}

function decodeCandidate(bytes) {
  if (bytes.length === 0 || bytes.length > MAX_CANDIDATE_BYTES) {
    throw new CalibrationError(
      "candidate_size",
      `candidate must contain 1..${MAX_CANDIDATE_BYTES} bytes`,
    );
  }
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    throw new CalibrationError("invalid_candidate_json", String(error));
  }
  exactKeys(value, ["schema_version", "fixture_id", "files"], "candidate");
  if (value.schema_version !== 1 || value.fixture_id !== FIXTURE_ID) {
    throw new CalibrationError("invalid_candidate_binding", "candidate binding is not exact");
  }
  if (!Array.isArray(value.files) || value.files.length !== 1) {
    throw new CalibrationError("invalid_candidate_shape", "candidate must contain exactly one file");
  }
  const file = value.files[0];
  exactKeys(file, ["path", "content"], "candidate.files[0]");
  if (file.path !== CANDIDATE_PATH || typeof file.content !== "string") {
    throw new CalibrationError("invalid_candidate_binding", "candidate file binding is not exact");
  }
  const sourceBytes = Buffer.from(file.content, "utf8");
  if (sourceBytes.length === 0 || sourceBytes.length > MAX_SOURCE_BYTES) {
    throw new CalibrationError(
      "source_size",
      `source must contain 1..${MAX_SOURCE_BYTES} UTF-8 bytes`,
    );
  }
  return { value, sourceBytes };
}

function parseOptions(arguments_) {
  const values = new Map();
  for (let index = 0; index < arguments_.length; index += 2) {
    const flag = arguments_[index];
    const value = arguments_[index + 1];
    if (!["--fixture", "--candidate", "--report", "--timeout-ms"].includes(flag) || value === undefined) {
      throw new CalibrationError(
        "invalid_arguments",
        "usage: codegen_calibration.mjs --fixture DIR --candidate FILE --report FILE [--timeout-ms N]",
      );
    }
    if (values.has(flag)) {
      throw new CalibrationError("invalid_arguments", `duplicate option ${flag}`);
    }
    values.set(flag, value);
  }
  for (const required of ["--fixture", "--candidate", "--report"]) {
    if (!values.has(required)) {
      throw new CalibrationError("invalid_arguments", `missing ${required}`);
    }
  }
  const timeoutText = values.get("--timeout-ms") ?? String(DEFAULT_TIMEOUT_MS);
  const timeoutMs = Number(timeoutText);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 300_000) {
    throw new CalibrationError("invalid_arguments", "timeout must be an integer from 1000 to 300000 ms");
  }
  return {
    fixture: resolve(values.get("--fixture")),
    candidate: resolve(values.get("--candidate")),
    report: resolve(values.get("--report")),
    timeoutMs,
  };
}

function appendBounded(chunks, state, bytes) {
  if (state.retained >= MAX_COMMAND_OUTPUT_BYTES) {
    state.truncated = true;
    return;
  }
  const remaining = MAX_COMMAND_OUTPUT_BYTES - state.retained;
  const retained = bytes.subarray(0, remaining);
  chunks.push(retained);
  state.retained += retained.length;
  state.truncated ||= retained.length !== bytes.length;
}

async function runCommand(command, args, cwd, timeoutMs) {
  const startedAt = new Date().toISOString();
  const started = process.hrtime.bigint();
  const stdout = [];
  const stderr = [];
  const stdoutState = { retained: 0, truncated: false };
  const stderrState = { retained: 0, truncated: false };
  const inheritedEnvironment = Object.fromEntries(
    SUBPROCESS_ENVIRONMENT_ALLOWLIST.flatMap((name) =>
      process.env[name] === undefined ? [] : [[name, process.env[name]]],
    ),
  );
  const child = spawn(command, args, {
    cwd,
    detached: process.platform !== "win32",
    env: {
      ...inheritedEnvironment,
      CARGO_NET_OFFLINE: "true",
      RUST_BACKTRACE: "0",
      LANG: "C",
      LC_ALL: "C",
    },
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (bytes) => appendBounded(stdout, stdoutState, bytes));
  child.stderr.on("data", (bytes) => appendBounded(stderr, stderrState, bytes));

  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    try {
      if (process.platform === "win32") {
        child.kill("SIGKILL");
      } else {
        process.kill(-child.pid, "SIGKILL");
      }
    } catch {
      child.kill("SIGKILL");
    }
  }, timeoutMs);
  const terminal = await new Promise((resolveTerminal, rejectTerminal) => {
    child.once("error", rejectTerminal);
    child.once("close", (code, signal) => resolveTerminal({ code, signal }));
  });
  clearTimeout(timer);
  const elapsedMs = Number((process.hrtime.bigint() - started) / 1_000_000n);
  return {
    argv: [command, ...args],
    cwd_role: "isolated_candidate_root",
    started_at: startedAt,
    elapsed_ms: elapsedMs,
    exit_code: terminal.code,
    signal: terminal.signal,
    timed_out: timedOut,
    stdout: Buffer.concat(stdout).toString("utf8"),
    stdout_truncated: stdoutState.truncated,
    stderr: Buffer.concat(stderr).toString("utf8"),
    stderr_truncated: stderrState.truncated,
    passed: terminal.code === 0 && !timedOut,
  };
}

async function writeCreateNew(path, value) {
  await mkdir(resolve(path, ".."), { recursive: true });
  const handle = await open(path, "wx", 0o600);
  try {
    await handle.writeFile(value);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function evaluate(options) {
  if (basename(options.fixture) !== FIXTURE_ID) {
    throw new CalibrationError("invalid_fixture", `fixture directory must end in ${FIXTURE_ID}`);
  }
  const [candidateBytes, taskBytes, acceptanceBytes, promptBytes, evaluatorBytes] = await Promise.all([
    readFile(options.candidate),
    readFile(join(options.fixture, "task.md")),
    readFile(join(options.fixture, "acceptance.rs")),
    readFile(
      resolve(
        options.fixture,
        "../../../prompts/codegen-calibration-literal-stream/1.0.0/manifest.json",
      ),
    ),
    readFile(new URL(import.meta.url)),
  ]);
  const candidate = decodeCandidate(candidateBytes);
  const inputDigest = sha256(
    Buffer.concat([candidateBytes, taskBytes, acceptanceBytes, promptBytes, evaluatorBytes]),
  );
  const candidateDigest = sha256(candidateBytes);
  const sourceDigest = sha256(candidate.sourceBytes);
  const workspace = await mkdtemp(join(tmpdir(), "birdcode-codegen-calibration-"));
  const commands = [];
  try {
    await mkdir(join(workspace, "src"), { recursive: true });
    await mkdir(join(workspace, "tests"), { recursive: true });
    await writeFile(join(workspace, "Cargo.toml"), CARGO_MANIFEST, { mode: 0o600 });
    await writeFile(join(workspace, "src/lib.rs"), candidate.sourceBytes, { mode: 0o600 });
    await writeFile(join(workspace, "tests/acceptance.rs"), acceptanceBytes, { mode: 0o600 });

    for (const [command, args] of [
      ["cargo", ["fmt", "--all", "--", "--check"]],
      ["cargo", ["test", "--offline", "--all-targets"]],
      ["cargo", ["clippy", "--offline", "--all-targets", "--", "-D", "warnings"]],
    ]) {
      const result = await runCommand(command, args, workspace, options.timeoutMs);
      commands.push(result);
      if (!result.passed) break;
    }
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
  const report = {
    schema_version: 1,
    fixture_id: FIXTURE_ID,
    evaluator: EVALUATOR_ID,
    evaluator_sha256: sha256(evaluatorBytes),
    evaluator_input_sha256: inputDigest,
    candidate_sha256: candidateDigest,
    source_sha256: sourceDigest,
    task_sha256: sha256(taskBytes),
    acceptance_sha256: sha256(acceptanceBytes),
    prompt_manifest_sha256: sha256(promptBytes),
    environment: {
      platform: process.platform,
      architecture: process.arch,
      node: process.version,
      network_policy: "outer_execution_sandbox_plus_cargo_offline",
      candidate_workspace: "ephemeral_and_removed_after_capture",
      subprocess_environment_allowlist: SUBPROCESS_ENVIRONMENT_ALLOWLIST,
    },
    commands,
    status: commands.length === 3 && commands.every((command) => command.passed) ? "passed" : "failed",
  };
  const encoded = `${JSON.stringify(report, null, 2)}\n`;
  await writeCreateNew(options.report, encoded);
  return { report, reportSha256: sha256(Buffer.from(encoded)) };
}

async function main() {
  let options;
  try {
    options = parseOptions(process.argv.slice(2));
    const result = await evaluate(options);
    process.stdout.write(
      `${JSON.stringify({ status: result.report.status, report_sha256: result.reportSha256 })}\n`,
    );
    if (result.report.status !== "passed") process.exitCode = 1;
  } catch (error) {
    const kind = error instanceof CalibrationError ? error.kind : "infrastructure";
    const message = error instanceof Error ? error.message : String(error);
    if (options?.report) {
      const failure = `${JSON.stringify(
        {
          schema_version: 1,
          fixture_id: FIXTURE_ID,
          evaluator: EVALUATOR_ID,
          status: "setup_failed",
          failure: { kind, message },
        },
        null,
        2,
      )}\n`;
      try {
        await writeCreateNew(options.report, failure);
      } catch {
        // The original typed failure remains authoritative when the report path
        // was already occupied or could not be created.
      }
    }
    process.stderr.write(`codegen calibration ${kind}: ${message}\n`);
    process.exitCode = 1;
  }
}

await main();
