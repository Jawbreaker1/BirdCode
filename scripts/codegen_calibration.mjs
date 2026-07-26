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
import { basename, dirname, join, resolve } from "node:path";
import { TextDecoder } from "node:util";

const MAX_CANDIDATE_BYTES = 128 * 1024;
const MAX_SOURCE_BYTES = 64 * 1024;
const MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 60_000;
const FIXTURE_ID = "literal-stream-v1";
const CANDIDATE_PATH = "src/lib.rs";
const EVALUATOR_ID = "birdcode.codegen-calibration/3";
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

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

function evaluationLimits(timeoutMs) {
  return {
    max_candidate_bytes: MAX_CANDIDATE_BYTES,
    max_source_bytes: MAX_SOURCE_BYTES,
    max_command_stdout_bytes: MAX_COMMAND_OUTPUT_BYTES,
    max_command_stderr_bytes: MAX_COMMAND_OUTPUT_BYTES,
    command_timeout_ms: timeoutMs,
  };
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
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new CalibrationError("invalid_candidate_encoding", String(error));
  }
  let value;
  try {
    value = JSON.parse(text);
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

async function readCandidateBytes(path) {
  const handle = await open(path, "r");
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile()) {
      throw new CalibrationError("invalid_candidate_file", "candidate must be a regular file");
    }
    const bytes = Buffer.alloc(MAX_CANDIDATE_BYTES + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const result = await handle.read(bytes, offset, bytes.length - offset, null);
      if (result.bytesRead === 0) break;
      offset += result.bytesRead;
    }
    return bytes.subarray(0, offset);
  } finally {
    await handle.close();
  }
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
      try {
        child.kill("SIGKILL");
      } catch {
        // The process may have terminated between timeout observation and kill.
      }
    }
  }, timeoutMs);
  let terminal;
  try {
    terminal = await new Promise((resolveTerminal, rejectTerminal) => {
      child.once("error", rejectTerminal);
      child.once("close", (code, signal) => resolveTerminal({ code, signal }));
    });
  } finally {
    clearTimeout(timer);
  }
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

async function reserveReport(path) {
  await mkdir(dirname(path), { recursive: true });
  try {
    return await open(path, "wx", 0o600);
  } catch (error) {
    if (error && typeof error === "object" && error.code === "EEXIST") {
      throw new CalibrationError("report_exists", `report path already exists: ${path}`);
    }
    throw error;
  }
}

async function finalizeReservedReport(handle, value) {
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
    readCandidateBytes(options.candidate),
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
  const candidateDigest = sha256(candidateBytes);
  const sourceDigest = sha256(candidate.sourceBytes);
  const evaluatorDigest = sha256(evaluatorBytes);
  const taskDigest = sha256(taskBytes);
  const acceptanceDigest = sha256(acceptanceBytes);
  const promptDigest = sha256(promptBytes);
  const limits = evaluationLimits(options.timeoutMs);
  const inputBinding = {
    schema_version: 1,
    evaluator: EVALUATOR_ID,
    fixture_id: FIXTURE_ID,
    evaluator_sha256: evaluatorDigest,
    candidate_sha256: candidateDigest,
    source_sha256: sourceDigest,
    task_sha256: taskDigest,
    acceptance_sha256: acceptanceDigest,
    prompt_manifest_sha256: promptDigest,
    limits,
  };
  const inputDigest = sha256(Buffer.from(canonicalJson(inputBinding)));
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
    evaluator_sha256: evaluatorDigest,
    evaluator_input_encoding: "sorted-key-json-v1",
    evaluator_input_sha256: inputDigest,
    candidate_sha256: candidateDigest,
    source_sha256: sourceDigest,
    task_sha256: taskDigest,
    acceptance_sha256: acceptanceDigest,
    prompt_manifest_sha256: promptDigest,
    limits,
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
  return { report, encoded, reportSha256: sha256(Buffer.from(encoded)) };
}

async function main() {
  let options;
  let reportHandle;
  let reportFinalizationStarted = false;
  try {
    options = parseOptions(process.argv.slice(2));
    reportHandle = await reserveReport(options.report);
    const result = await evaluate(options);
    reportFinalizationStarted = true;
    await finalizeReservedReport(reportHandle, result.encoded);
    reportHandle = undefined;
    process.stdout.write(
      `${JSON.stringify({ status: result.report.status, report_sha256: result.reportSha256 })}\n`,
    );
    if (result.report.status !== "passed") process.exitCode = 1;
  } catch (error) {
    const kind = error instanceof CalibrationError ? error.kind : "infrastructure";
    const message = error instanceof Error ? error.message : String(error);
    if (reportHandle && !reportFinalizationStarted) {
      const failure = `${JSON.stringify(
        {
          schema_version: 1,
          fixture_id: FIXTURE_ID,
          evaluator: EVALUATOR_ID,
          limits: evaluationLimits(options.timeoutMs),
          status: "setup_failed",
          failure: { kind, message },
        },
        null,
        2,
      )}\n`;
      try {
        reportFinalizationStarted = true;
        await finalizeReservedReport(reportHandle, failure);
        reportHandle = undefined;
      } catch {
        // The original typed failure remains authoritative when the reserved
        // report cannot be finalized.
      }
    }
    process.stderr.write(`codegen calibration ${kind}: ${message}\n`);
    process.exitCode = 1;
  } finally {
    if (reportHandle) {
      try {
        await reportHandle.close();
      } catch {
        // A failed finalization may already have closed the reservation.
      }
    }
  }
}

await main();
