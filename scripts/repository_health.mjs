import { lstat, readFile } from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

export const REPOSITORY_HEALTH_SCHEMA_VERSION = 1;
export const DEFAULT_CONFIG_PATH = "config/repository-health.v1.json";

function requireExactKeys(value, expected, label) {
  const actual = Object.keys(value).toSorted();
  const required = [...expected].toSorted();
  if (actual.length !== required.length || actual.some((key, index) => key !== required[index])) {
    throw new TypeError(`${label} must contain exactly: ${required.join(", ")}`);
  }
}

function requirePositiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive safe integer`);
  }
}

function requireRepositoryPath(value, label) {
  if (
    typeof value !== "string"
    || value.length === 0
    || path.posix.isAbsolute(value)
    || value.split("/").includes("..")
    || value.includes("\\")
  ) {
    throw new TypeError(`${label} must be a normalized repository-relative path`);
  }
}

export function validateRepositoryHealthConfig(config) {
  if (config === null || typeof config !== "object" || Array.isArray(config)) {
    throw new TypeError("repository-health config must be an object");
  }
  requireExactKeys(config, ["schema_version", "source_limits", "debt"], "config");
  if (config.schema_version !== REPOSITORY_HEALTH_SCHEMA_VERSION) {
    throw new TypeError(
      `repository-health schema_version must be ${REPOSITORY_HEALTH_SCHEMA_VERSION}`,
    );
  }
  if (
    config.source_limits === null
    || typeof config.source_limits !== "object"
    || Array.isArray(config.source_limits)
  ) {
    throw new TypeError("source_limits must be an object");
  }
  if (!Array.isArray(config.debt)) {
    throw new TypeError("debt must be an array");
  }

  for (const [extension, limit] of Object.entries(config.source_limits)) {
    if (!/^[a-z0-9]+$/u.test(extension)) {
      throw new TypeError(`invalid source extension: ${extension}`);
    }
    requirePositiveInteger(limit, `source limit for .${extension}`);
  }
  const debtPaths = new Set();
  for (const [index, entry] of config.debt.entries()) {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new TypeError(`debt[${index}] must be an object`);
    }
    requireExactKeys(entry, ["path", "ceiling_lines"], `debt[${index}]`);
    const filePath = entry.path;
    const ceiling = entry.ceiling_lines;
    requireRepositoryPath(filePath, `debt ceiling path ${JSON.stringify(filePath)}`);
    requirePositiveInteger(ceiling, `debt ceiling for ${filePath}`);
    if (debtPaths.has(filePath)) {
      throw new TypeError(`duplicate debt ceiling path: ${filePath}`);
    }
    debtPaths.add(filePath);
    const extension = path.posix.extname(filePath).slice(1);
    const defaultLimit = config.source_limits[extension];
    if (defaultLimit === undefined) {
      throw new TypeError(`debt ceiling has no source limit: ${filePath}`);
    }
    if (ceiling <= defaultLimit) {
      throw new TypeError(
        `debt ceiling for ${filePath} must exceed its default limit of ${defaultLimit}`,
      );
    }
  }
  return config;
}

export function countSourceLines(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError("source bytes must be a Uint8Array");
  }
  if (bytes.byteLength === 0) {
    return 0;
  }
  let lines = 0;
  for (const byte of bytes) {
    if (byte === 0x0a) {
      lines += 1;
    }
  }
  if (bytes.at(-1) !== 0x0a) {
    lines += 1;
  }
  return lines;
}

export function evaluateRepositoryHealth({
  config,
  files,
  legacyTargetExists = false,
  inspectionViolations = [],
}) {
  validateRepositoryHealthConfig(config);
  if (!Array.isArray(files)) {
    throw new TypeError("files must be an array");
  }
  if (!Array.isArray(inspectionViolations)) {
    throw new TypeError("inspectionViolations must be an array");
  }

  const violations = [...inspectionViolations];
  if (legacyTargetExists) {
    violations.push(
      "repo-local target/ exists; use `npm run cargo -- ...` and remove the regenerable legacy cache",
    );
  }

  const debtCeilings = new Map(
    config.debt.map((entry) => [entry.path, entry.ceiling_lines]),
  );
  const observed = new Map();
  for (const file of files) {
    requireRepositoryPath(file.path, "source file path");
    if (!Number.isSafeInteger(file.lines) || file.lines < 0) {
      throw new TypeError(`line count for ${file.path} must be a non-negative safe integer`);
    }
    if (observed.has(file.path)) {
      throw new TypeError(`duplicate source file observation: ${file.path}`);
    }
    observed.set(file.path, file.lines);

    const extension = path.posix.extname(file.path).slice(1);
    const defaultLimit = config.source_limits[extension];
    if (defaultLimit === undefined) {
      continue;
    }
    const debtCeiling = debtCeilings.get(file.path);
    if (debtCeiling === undefined) {
      if (file.lines > defaultLimit) {
        violations.push(
          `${file.path} has ${file.lines} lines; new source files are limited to ${defaultLimit}`,
        );
      }
      continue;
    }
    if (file.lines > debtCeiling) {
      violations.push(
        `${file.path} grew to ${file.lines} lines; its debt ceiling is ${debtCeiling}`,
      );
    } else if (file.lines < debtCeiling) {
      violations.push(
        `${file.path} shrank to ${file.lines} lines; lower its debt ceiling from ${debtCeiling}`,
      );
    }
  }

  for (const [filePath, ceiling] of debtCeilings) {
    if (!observed.has(filePath)) {
      violations.push(
        `${filePath} is absent; remove its stale debt ceiling of ${ceiling}`,
      );
    }
  }

  const largestSources = files
    .filter((file) => config.source_limits[path.posix.extname(file.path).slice(1)] !== undefined)
    .toSorted((left, right) => right.lines - left.lines || left.path.localeCompare(right.path))
    .slice(0, 10);

  violations.sort((left, right) => left.localeCompare(right));
  return {
    healthy: violations.length === 0,
    source_files: files.length,
    violations,
    largest_sources: largestSources,
  };
}

function runGit(root, arguments_) {
  const result = spawnSync("git", arguments_, {
    cwd: root,
    encoding: null,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(
      `git ${arguments_.join(" ")} failed: ${result.stderr.toString("utf8").trim()}`,
    );
  }
  return result.stdout;
}

export function resolveRepositoryRoot(cwd = process.cwd()) {
  return runGit(cwd, ["rev-parse", "--show-toplevel"]).toString("utf8").trim();
}

async function exists(filePath) {
  try {
    await lstat(filePath);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

export async function inspectRepositoryHealth({
  root,
  configPath = DEFAULT_CONFIG_PATH,
}) {
  const config = validateRepositoryHealthConfig(
    JSON.parse(await readFile(path.join(root, configPath), "utf8")),
  );
  const trackedAndUntracked = runGit(
    root,
    ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
  );
  const repositoryPaths = trackedAndUntracked
    .toString("utf8")
    .split("\0")
    .filter((candidate) => candidate.length > 0);
  const files = [];
  const inspectionViolations = [];

  for (const repositoryPath of repositoryPaths) {
    const extension = path.posix.extname(repositoryPath).slice(1);
    if (config.source_limits[extension] === undefined) {
      continue;
    }
    const absolutePath = path.join(root, ...repositoryPath.split("/"));
    let metadata;
    try {
      metadata = await lstat(absolutePath);
    } catch (error) {
      if (error?.code === "ENOENT") {
        continue;
      }
      throw error;
    }
    if (metadata.isSymbolicLink() || !metadata.isFile()) {
      inspectionViolations.push(`${repositoryPath} must be a regular source file`);
      continue;
    }
    files.push({
      path: repositoryPath,
      lines: countSourceLines(await readFile(absolutePath)),
    });
  }

  return evaluateRepositoryHealth({
    config,
    files,
    legacyTargetExists: await exists(path.join(root, "target")),
    inspectionViolations,
  });
}

async function main() {
  const root = resolveRepositoryRoot();
  const report = await inspectRepositoryHealth({ root });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!report.healthy) {
    process.exitCode = 1;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((error) => {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  });
}
