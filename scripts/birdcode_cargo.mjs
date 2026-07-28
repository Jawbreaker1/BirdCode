import { runCachedCommand } from "./birdcode_cached_command.mjs";
import { inspectRepositoryHealth, resolveRepositoryRoot } from "./repository_health.mjs";

async function main() {
  const repositoryHealth = await inspectRepositoryHealth({
    root: resolveRepositoryRoot(),
  });
  if (!repositoryHealth.healthy) {
    throw new Error(
      `Repository health check failed:\n${repositoryHealth.violations.map((violation) => `- ${violation}`).join("\n")}`,
    );
  }
  const cargo = process.env.BIRDCODE_CARGO_BIN ?? "cargo";
  const result = await runCachedCommand({
    command: cargo,
    args: process.argv.slice(2),
    cwd: process.cwd(),
    environment: {
      ...process.env,
      CARGO_INCREMENTAL: process.env.CARGO_INCREMENTAL ?? "0",
    },
  });
  if (result.signal) {
    process.stderr.write(`Cargo terminated by ${result.signal}\n`);
  }
  process.exitCode = result.status;
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
