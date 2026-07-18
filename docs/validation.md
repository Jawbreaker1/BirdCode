# Target validation and Codex comparison

This is the acceptance policy for backend and evaluation work. The foundation
currently runs deterministic build, protocol, persistence, CLI, desktop,
prompt-contract, and mock-HTTP backend checks. A standalone LM Studio semantic
router evaluation exists; comparable multi-backend run orchestration is not yet
wired into the daemon.

Codex with the best available Sol/Ultra configuration is used as an independent
development reference and is planned as an optional comparison backend in the
product.

## Comparable run

A comparable run begins from a versioned `RunSpec` containing:

- user task and compiled context manifest;
- Git commit or content snapshot;
- workspace and platform manifest;
- allowed tools, permissions, and network policy;
- time, token, concurrency, and retry budgets;
- acceptance tests and semantic review rubric.

Candidates run in isolated worktrees or overlays. The system stores raw backend
events, normalized events, patches, artifacts, tests, timings, and reported
usage.

## Evaluation

Deterministic checks decide everything they can: compilation, tests, linting,
schema validity, file scope, exit status, and artifact comparison. Semantic
qualities are judged blind from a structured rubric with evidence references.

The bundled semantic-router catalog covers clarify, answer, inspect, and change
actions; direct and delegated strategies; read-only and write access; genuine
English, Japanese, and Arabic intent; multilingual data; repository prompt
injection; and a zero-delegation limit. Acceptance includes required evidence
sections and bounded clarification/subtask counts in addition to the three
route axes. Its pure catalog and comparison tests live in a normal Cargo test
target and therefore run under `cargo test --workspace`.

Live inference requires a create-new report path that is reserved with valid,
synced JSON before the first HTTP request. The reservation is finalized as a
complete `passed` or `failed` report before the process returns success or a
nonzero status. Each versioned report records the source revision, timestamp,
runner/platform identity, LM Studio version and version source, the exact
selected OpenAI identity plus bounded matching native identity/quantization
evidence, SHA-256 digests of the complete discovery response bodies, raw
inference evidence, manifest and schema hashes, raw case-file digests,
canonical prompt-input digests, and validated or rejected output. Full model
inventories, unrelated model configuration, and local model paths are omitted.
Configured URL user information is rejected; every retained endpoint is also
credential-, query-, and fragment-free. Existing evidence cannot be overwritten
accidentally, and discovery, inference, validation, and expectation failures are
retained before a nonzero exit.

Sol/Ultra can generate, critique, or compare work, but never serves as the only
authority for its own output. Independent agents, alternative providers, and
deterministic tests counter correlated failure modes.

## Clean-room boundary

BirdCode may use public Codex documentation, documented protocols, and
externally observable behavior. It must not inspect or copy Codex implementation
source. The Codex bridge is an optional backend adapter and is not the
implementation of BirdCode's own runtime.
